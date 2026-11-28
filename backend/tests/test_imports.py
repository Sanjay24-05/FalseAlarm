"""Every module imports on its own, so no import order hides a cycle."""

import pkgutil
import subprocess
import sys

import pytest

import false_alarm

MODULES = sorted(
    info.name for info in pkgutil.walk_packages(false_alarm.__path__, prefix="false_alarm.")
)


def test_the_package_has_modules():
    assert "false_alarm.planner.actions" in MODULES


def test_each_module_imports_in_a_fresh_interpreter():
    script = (
        "import importlib, sys\n"
        "failed = []\n"
        "for name in sys.argv[1:]:\n"
        "    for loaded in [key for key in sys.modules if key.startswith('false_alarm')]:\n"
        "        del sys.modules[loaded]\n"
        "    try:\n"
        "        importlib.import_module(name)\n"
        "    except Exception as exc:\n"
        "        failed.append(f'{name}: {type(exc).__name__}: {exc}')\n"
        "print('\\n'.join(failed))\n"
        "sys.exit(1 if failed else 0)\n"
    )
    result = subprocess.run([sys.executable, "-c", script, *MODULES], capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("name", ["false_alarm.planner", "false_alarm.planner.actions", "false_alarm.planner.playbooks"])
def test_planner_modules_import_first(name):
    result = subprocess.run([sys.executable, "-c", f"import {name}"], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
