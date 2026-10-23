"""Tools the planner is allowed to name. Anything else is rejected."""

from __future__ import annotations

ALLOWED_TOOLS = frozenset(
    {
        "query_authentication",
        "query_firewall",
        "query_endpoint",
        "query_dns",
        "query_related_alerts",
        "lookup_threat_intel",
        "expand_time_window",
        "finish",
    }
)
