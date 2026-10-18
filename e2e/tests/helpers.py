import json
import os
import shlex
from typing import Optional

import jsonschema
from referencing import Registry, Resource

# Vendored workspace schemas (see docs/output-schema.md, "Vendored schemas").
DOCS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "docs")
SCHEMA_PATH = os.path.join(DOCS_DIR, "schema.json")
NETWORK_CONTEXT_SCHEMA_PATH = os.path.join(DOCS_DIR, "network_context.schema.json")

# Bloodhound-local invariant, stricter than the workspace contract: every
# event carries the legacy event.layer with one of these values.
BLOODHOUND_LAYERS = {"intent", "tooling", "behavior"}

_schema = None
_validators = None


def python_command(script: str, *, sudo: bool = False) -> str:
    """Build a shell-safe command for running Python source remotely."""
    prefix = "sudo " if sudo else ""
    return f"{prefix}python3 -c {shlex.quote(script)}"


def get_schema():
    global _schema
    if _schema is None:
        with open(SCHEMA_PATH) as f:
            _schema = json.load(f)
    return _schema


def get_validators() -> tuple[jsonschema.Draft7Validator, jsonschema.Draft7Validator]:
    """Return (base, network_context) validators sharing one base schema.

    network_context.schema.json references the base by its $id, which
    resolves to docs/schema.json through the registry.
    """
    global _validators
    if _validators is None:
        base = get_schema()
        with open(NETWORK_CONTEXT_SCHEMA_PATH) as f:
            network = json.load(f)
        registry = Registry().with_resources(
            (schema["$id"], Resource.from_contents(schema))
            for schema in (base, network)
        )
        _validators = (
            jsonschema.Draft7Validator(base, registry=registry),
            jsonschema.Draft7Validator(network, registry=registry),
        )
    return _validators


def validate_event(event: dict) -> None:
    """Validate an event against the base schema, its extension, and local invariants."""
    base, network_context = get_validators()
    base.validate(event)
    if event["event"]["name"] == "exec_entry_network_context":
        network_context.validate(event)
    layer = event["event"].get("layer")
    if layer not in BLOODHOUND_LAYERS:
        raise jsonschema.ValidationError(
            f"event.layer {layer!r} is not one of {sorted(BLOODHOUND_LAYERS)}"
        )


def validate_all_events(events: list[dict]) -> None:
    """Validate all events against the schema."""
    for i, event in enumerate(events):
        try:
            validate_event(event)
        except jsonschema.ValidationError as e:
            raise AssertionError(
                f"Event #{i} failed schema validation: {e.message}\n"
                f"Event: {json.dumps(event, indent=2)}"
            )


def filter_events(
    events: list[dict],
    event_type: Optional[str] = None,
    name: Optional[str] = None,
    layer: Optional[str] = None,
    pid: Optional[int] = None,
    comm: Optional[str] = None,
) -> list[dict]:
    """Filter events by criteria."""
    result = events
    if event_type:
        result = [e for e in result if e.get("event", {}).get("type") == event_type]
    if name:
        result = [e for e in result if e.get("event", {}).get("name") == name]
    if layer:
        result = [e for e in result if e.get("event", {}).get("layer") == layer]
    if pid:
        result = [e for e in result if e.get("header", {}).get("pid") == pid]
    if comm:
        result = [e for e in result if e.get("header", {}).get("comm") == comm]
    return result


def assert_event_exists(
    events: list[dict],
    event_type: Optional[str] = None,
    name: Optional[str] = None,
    layer: Optional[str] = None,
    msg: str = "",
) -> dict:
    """Assert at least one event matching criteria exists. Return the first match."""
    matches = filter_events(events, event_type=event_type, name=name, layer=layer)
    assert len(matches) > 0, (
        f"Expected event (type={event_type}, name={name}, layer={layer}) "
        f"not found. {msg}\n"
        f"Available events: {[e.get('event') for e in events[:20]]}"
    )
    return matches[0]


def assert_no_event(
    events: list[dict],
    event_type: Optional[str] = None,
    name: Optional[str] = None,
    layer: Optional[str] = None,
    msg: str = "",
) -> None:
    """Assert no events match the criteria."""
    matches = filter_events(events, event_type=event_type, name=name, layer=layer)
    assert len(matches) == 0, (
        f"Unexpected event found (type={event_type}, name={name}, layer={layer}). "
        f"{msg}\nFound: {json.dumps(matches[0], indent=2)}"
    )


def assert_auid_filter(events: list[dict], target_auid: int) -> None:
    """Assert all events have the correct auid, with documented exceptions.

    - PACKET events may legitimately carry auid=0 when packet→process
      correlation fails (the socket tracking table has no match for the
      5-tuple, e.g., short-lived processes).
    - HEARTBEAT events carry auid=0 as a sentinel: the event is a
      daemon-scoped pulse not attributable to any user process.
    - LIFECYCLE events forward the triggering event's auid and therefore
      match `target_auid` in normal operation.
    """
    for event in events:
        auid = event.get("header", {}).get("auid", -1)
        event_type = event.get("event", {}).get("type", "")
        if event_type == "PACKET":
            assert auid in (target_auid, 0), (
                f"PACKET event has unexpected auid={auid}"
            )
        elif event_type == "HEARTBEAT":
            # HEARTBEAT is a daemon-scoped pulse; auid=0 is the
            # documented sentinel (see docs/output-schema.md).
            assert auid == 0, (
                f"HEARTBEAT event has unexpected auid={auid} "
                f"(expected 0 sentinel)"
            )
        else:
            assert auid == target_auid, (
                f"Event has wrong auid={auid}, expected {target_auid}: "
                f"{json.dumps(event.get('event'), indent=2)}"
            )
