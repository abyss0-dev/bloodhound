"""Pinned network-context schema and successful-exec replay invariants."""
import json
from pathlib import Path

from jsonschema import Draft7Validator, RefResolver

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_DIR = ROOT / "docs/spec/behavior_event"
BASE = json.loads((SCHEMA_DIR / "behavior_event.schema.json").read_text())
NETWORK = json.loads((SCHEMA_DIR / "network_context.schema.json").read_text())
VALIDATOR = Draft7Validator(
    NETWORK,
    resolver=RefResolver.from_schema(
        NETWORK,
        store={"https://workspace.invalid/spec/behavior_event/behavior_event.schema.json": BASE},
    ),
)


def context(status="complete", netns=None, pid=100, start=123, timestamp=456):
    if netns is None and status == "complete":
        netns = {"device": 0, "inode": 7}
    return {
        "header": {"timestamp": timestamp, "auid": 1000, "sessionid": 1,
                   "pid": pid, "comm": "worker", "process_ref":
                   {"tgid": pid, "start_boottime_ns": start}},
        "event": {"type": "META", "name": "exec_entry_network_context", "layer": "behavior"},
        "args": {"record_version": 1, "actor": {"tgid": pid, "start_boottime_ns": start},
                 "entry_timestamp_ns": timestamp, "netns": netns, "status": status},
    }


def test_network_context_schema_positive_and_status_null_negative():
    assert VALIDATOR.is_valid(context())
    assert VALIDATOR.is_valid(context("unavailable", None))
    assert VALIDATOR.is_valid(context("changed", None))
    incomplete = context()
    incomplete["args"]["netns"] = None
    assert not VALIDATOR.is_valid(incomplete)
    assert not VALIDATOR.is_valid(context("unavailable", {"device": 0, "inode": 7}))


def test_context_must_pair_successful_exec_by_exact_actor_and_entry_time():
    ctx = context()
    success_exec = {"header": {"pid": 100, "timestamp": 456,
                                "process_ref": {"tgid": 100, "start_boottime_ns": 123}},
                    "event": {"type": "TRACEPOINT", "name": "execve"},
                    "return_code": 0}

    def matching_pairs(contexts, execs):
        return [
            (context_event, exec_event)
            for context_event in contexts
            for exec_event in execs
            if exec_event.get("return_code") == 0
            and context_event["header"]["pid"] == exec_event["header"]["pid"]
            and context_event["args"]["actor"]["start_boottime_ns"]
            == exec_event["header"]["process_ref"]["start_boottime_ns"]
            and context_event["header"]["timestamp"] == exec_event["header"]["timestamp"]
            and context_event["args"]["entry_timestamp_ns"] == exec_event["header"]["timestamp"]
        ]

    assert len(matching_pairs([ctx], [success_exec])) == 1
    assert len(matching_pairs([ctx, context()], [success_exec])) == 2
    for mismatch in (
        {**success_exec, "return_code": -2},
        {**success_exec, "header": {**success_exec["header"], "pid": 101}},
        {**success_exec, "header": {**success_exec["header"], "timestamp": 457}},
        {**success_exec, "header": {**success_exec["header"],
            "process_ref": {"tgid": 100, "start_boottime_ns": 124}}},
    ):
        assert not matching_pairs([ctx], [mismatch])
