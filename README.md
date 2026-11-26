# False Alarm

False Alarm is a local SIEM investigation console. It ingests an alert, retrieves evidence through allowlisted tools, and writes a verdict, a timeline, and a report from the records that were actually stored. The planner decides which tool to call next. It does not invent log rows, timeline events, or verdicts.

The backend is a FastAPI service. The console is a Vite app that talks to it through `/api`. Scenario data lives in `data/scenarios`. Investigations are stored in SQLite.

## Architecture

An investigation has two separate jobs.

**Planner.** A playbook is chosen from the alert name, description, and MITRE techniques: `authentication`, `malware`, `outbound`, or `generic`. The next playbook action is the highest-priority unanswered question whose inputs are already known. If an LLM is configured, it may propose that action instead. The proposal must be one JSON tool call. An invalid response, including a tool outside the allowlist, is tried once more, then the playbook is used. The planner may filter by `user`, `host`, and `iocs`. The loop supplies the time window and the event limit.

The model can change the order of the investigation, not its extent. The playbook action replaces a proposal that finishes while questions are open, names no user, host, or indicator, or repeats a query that already ran. Once the remaining tool calls are only enough for the open questions and `finish`, only the playbook plans. A question counts as answered only when a query includes every filter the playbook would have used; a `question_id` from the model is ignored. Each replacement is in the audit trail with its reason.

Allowlisted tools:

- `query_authentication`
- `query_firewall`
- `query_endpoint`
- `query_dns`
- `query_related_alerts`
- `lookup_threat_intel`
- `expand_time_window`
- `finish`

**Deterministic evidence.** Each query tool calls a connector. Returned events are stored as observations. Correlation then builds a chronological timeline:

- `observed` events come from stored evidence.
- `inferred` events are links the correlator derived, and they cite the evidence ids they used.

Assessment rules assign the verdict, a qualitative confidence label, and whether to escalate. The report is composed from the stored alert, assessment, evidence, timeline, and audit trail. If any section cites an evidence id that was not stored, the whole report is replaced by a deterministic template. The model is not asked to write the verdict or the report.

Evidence `source` identifies the connector, for example `file:authentication`. `source_type` is the log family: `authentication`, `firewall`, `endpoint`, `dns`, `related_alerts`, or `threat_intel`.

A run stops for one of these reasons: `completed`, `tool_call_budget`, `time_budget`, `failed`, `unknown_tool`, or `interrupted`. When the API starts, any run a previous process left `running` is marked `failed` with `interrupted`, so run one API process per database. An alert has at most one running investigation: starting another returns the running one's id. Tool-call and time budgets finish with investigation status `budget_exhausted`. The defaults are 12 tool calls and 60 seconds. Each step is `completed` or `rejected`; a tool that raises fails the whole run.

The report has these sections: incident summary, alert details, triage, executive explanation, timeline, evidence, correlated indicators, threat intelligence, attack sequence, confidence and gaps, recommended actions, escalation, and audit trail. A section is text. The console also renders a section when its value is structured JSON.

## Run the API and the console

Python 3.12 and Node.js are required. Commands below start from the repository root. From `backend`, create the virtualenv and install the package if that has not been done yet:

```powershell
cd E:\FalseAlarm\backend
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -c requirements.lock -e ".[dev]"
.\.venv\Scripts\python.exe -m uvicorn false_alarm.main:app --host 127.0.0.1 --port 8000
```

The API listens on `http://127.0.0.1:8000`. Alerts and investigations are written to `backend/data/false_alarm.db` unless `FALSE_ALARM_DB_PATH` is set. Scenarios are read from `data/scenarios` unless `FALSE_ALARM_SCENARIOS_DIR` is set.

In another shell, start the console:

```powershell
cd E:\FalseAlarm\frontend
npm install
npm run dev
```

Vite serves `http://localhost:5173` and proxies `/api` to `http://127.0.0.1:8000`. Open that URL, load a scenario from the queue, open the alert, and start an investigation. The investigation page polls until the status is `completed`, `failed`, or `budget_exhausted`, then the report page shows all 13 sections.

Backend tests:

```powershell
cd E:\FalseAlarm\backend
.\.venv\Scripts\python.exe -m pytest
```

Console typecheck:

```powershell
cd E:\FalseAlarm\frontend
npx tsc --noEmit
```

## Offline demo

No API key is required. Leave the LLM variables unset. The playbook plans every step, and the file connector reads the scenario JSON.

| Scenario | What it contains | Verdict | Escalation |
| --- | --- | --- | --- |
| `account_compromise` | Repeated authentication failures, a success from the same external address, access to a sensitive file server, and an unusual outbound transfer | `confirmed_threat` | yes |
| `benign_vpn_login` | A mistyped password, then a sign-in from a known corporate VPN and ordinary file-server use | `likely_benign` | no |

Load either one with the queue buttons or with `POST /api/scenarios/{id}/load`, then `POST /api/investigations` with `{"alert_id": "..."}`. The catalog is `GET /api/scenarios`.

## Triage rules

Verdicts are labels. Confidence is `low`, `medium`, or `high`, not a probability. A missing reputation is unknown, not benign.

Every successful sign-in in the window is judged, not only the first. Access-stage signals are: three or more authentication failures for the user, a success from the same source as an earlier failure, a success from a source that is neither the user baseline nor a known-good range, or three or more accounts from one IP.

Later-action signals are: access to a high or critical asset outside the user's typical file servers, an unusual outbound transfer, endpoint activity marked malicious or high/critical, or a related alert of medium severity or higher. A later-action record counts only when it belongs to the alert's user, or names no person (or a machine account) and belongs to the alert's host or sign-in source; it does not precede the access; and the firewall did not block it. Harmful records that fail this are a material gap: they prevent `likely_benign` but do not confirm a threat. An outbound transfer counts when its destination has a negative local reputation, or when the byte count reaches the greater of 50,000,000 and five times that user's typical outbound volume.

- `likely_benign` when every successful authentication comes from a corporate VPN range, a scanner range, or a baseline source, there are fewer than three failures from any other source, and there is no later-action signal and no negative reputation. This does not escalate.
- `confirmed_threat` when at least one access-stage signal and at least one later-action signal are both present, and the benign case above does not apply. This always escalates.
- `suspicious` otherwise. This escalates when a material gap remains, or when a source outside the baseline and known-good ranges succeeded after three or more failures from that same source.

Material gaps are: no authentication events, threat intelligence not queried, a reputation stored as unknown, harmful activity that could not be attributed to the sign-in, or a query that reached its event limit. A query that reaches its limit keeps the newest events and rules out `likely_benign`. High confidence requires at least three evidence source types, no material gap, and a verdict of `confirmed_threat` or `likely_benign`.

Assessed severity is independent of the alert's original severity. `likely_benign` is `low` when authentication evidence exists, otherwise `informational`. Both a sensitive-asset access and an unusual outbound transfer make it `critical`. Either of those, or malicious endpoint activity, or a confirmed threat, makes it `high`. A suspicious case with none of those is `medium`.

## Indicators

Indicators are taken from the alert's structured fields and its text. IPv4 and IPv6 addresses are stored in canonical form; an `src_ip` or `dst_ip` that is not an address is dropped with a warning. A URL contributes only its host as a domain, and names ending in a file extension (`invoice.pdf`, `payload.dll`) or equal to the alert's username are not domains. Private, loopback, link-local, carrier-grade NAT, and unique-local ranges are internal; documentation ranges such as `203.0.113.0/24` count as external. Threat intelligence is looked up again whenever later evidence adds an indicator that has not been rated.

## LLM settings

The planner calls a model only when all of these are set. `FALSE_ALARM_LLM_ENABLED` must be `1`, `true`, `yes`, or `on`. The other three must be non-empty.

| Variable | Role |
| --- | --- |
| `FALSE_ALARM_LLM_ENABLED` | Turns the planner's model call on. Default is off. |
| `FALSE_ALARM_LLM_BASE_URL` | OpenAI-compatible base URL. `/chat/completions` is appended when the URL does not already end with that path. |
| `FALSE_ALARM_LLM_API_KEY` | Bearer token for that endpoint. |
| `FALSE_ALARM_LLM_MODEL` | Model name sent in the chat request. |

The offline demo runs with no key. If the model is enabled but the call fails or the JSON is not an allowlisted tool, the playbook action is used. Each call's timeout is the smaller of 20 seconds and the time left in the run's budget, and no call starts once the budget is spent. A failed call is logged and recorded in the audit trail by exception type only, never with the key, URL, or model text.

## HTTP contract

`POST /api/alerts` accepts one JSON object. A new alert is `201`. The same fingerprint is `200` with `duplicate: true`. Validation failure is `422` and the body is `{ "errors": [{ "field": "...", "message": "..." }] }` with no `detail` wrapper. `404` responses use `{ "detail": "..." }`.

`POST /api/alerts/upload` reads a multipart field named `file`. The file is one JSON object or an array. The response is `200` and `{ "results": [ ... ] }`. A bad item is `{ "errors": [...] }` and does not fail the rest of the batch. An empty or non-JSON file is `422`.

`GET /api/alerts` returns summaries. `verdict` is always present and is `null` until an investigation has assessed that alert. A stored alert includes a generated `id` and `iocs` as `{ "type", "value" }` objects. Warnings use the same `{ "field", "message" }` shape as errors.

`POST /api/investigations` with `{ "alert_id": "..." }` returns `202` and `{ "id", "status": "running" }`. `GET /api/investigations/{id}` is the document the console polls.

## Add a connector

v1 ships one connector, `FileConnector` in `backend/src/false_alarm/connectors/file_connector.py`. Every log family goes through the same call:

```python
result = connector.query(request)  # QueryRequest -> QueryResult
```

`QueryRequest` fields are `iocs`, `user`, `host`, `start`, `end`, and `limit`. `QueryResult` fields are `source`, `query`, `window`, `timestamp`, `events`, `truncated`.

`FileConnector.query` also takes `hard_cap`, which clamps `limit`. It reads one JSON file from each scenario directory, normalizes each record, filters by the request, and sets `source` to `file:<source_type>`. Threat-intelligence rows are matched on `iocs` and are not filtered by the time window. Other families are filtered by time, user, host, and IOCs.

A new connector implements that same `query(request) -> result` method and returns events with the normalized keys the rules already read: `timestamp`, `username`, `hostname`, `src_ip`, `dst_ip`, `dst_host`, `action`, `direction`, `bytes`, `severity`, `indicator`, `indicator_type`, `reputation`, `domains`, and `hashes`. There is no plugin registry. `execute_tool` in `backend/src/false_alarm/agent/tools.py` constructs `FileConnector` for each query tool. Point that call at the new connector for the log family it should serve.
