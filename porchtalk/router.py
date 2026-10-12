"""Deterministic offline routing policy. No networking or model execution."""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
from typing import Any

ALLOWED_CLASSES = frozenset({"PUBLIC", "SYNTHETIC", "PRIVATE"})
REMOTE_CLASSES = frozenset({"PUBLIC", "SYNTHETIC"})


class ScenarioError(ValueError):
    """Invalid input: no routing decision should be trusted."""


def _object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ScenarioError(f"{name} must be an object")
    return value


def _string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ScenarioError(f"{name} must be a nonempty string")
    return value


def _integer(value: Any, name: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ScenarioError(f"{name} must be an integer >= {minimum}")
    return value


def _boolean(value: Any, name: str) -> bool:
    if type(value) is not bool:
        raise ScenarioError(f"{name} must be a boolean")
    return value


def _time(value: Any) -> datetime:
    raw = _string(value, "expires_at")
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ScenarioError("expires_at must be ISO-8601 with a timezone") from exc
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ScenarioError("expires_at must include a timezone")
    return dt.astimezone(timezone.utc)


def load_scenario(payload: Any) -> dict[str, Any]:
    """Validate metadata only. Unknown fields are rejected to avoid silent drift."""
    source = _object(payload, "scenario")
    if set(source) != {"request", "offers", "grants"}:
        raise ScenarioError("scenario requires exactly request, offers, grants")
    request = _object(source["request"], "request")
    request_fields = {
        "request_id", "requester_id", "data_class", "min_quality_tier",
        "max_cost_units", "max_latency_ms", "max_energy_mwh", "allow_remote",
    }
    if set(request) != request_fields:
        raise ScenarioError("request fields do not match v0.1 schema")
    for key in ("request_id", "requester_id"):
        _string(request[key], key)
    if not isinstance(request["data_class"], str) or request["data_class"] not in ALLOWED_CLASSES:
        raise ScenarioError("data_class must be PUBLIC, SYNTHETIC, or PRIVATE")
    tier = _integer(request["min_quality_tier"], "min_quality_tier")
    if tier > 3:
        raise ScenarioError("min_quality_tier must be 0..3")
    for key in ("max_cost_units", "max_latency_ms", "max_energy_mwh"):
        _integer(request[key], key)
    _boolean(request["allow_remote"], "allow_remote")

    if not isinstance(source["offers"], list) or not isinstance(source["grants"], list):
        raise ScenarioError("offers and grants must be arrays")
    if len(source["offers"]) > 256 or len(source["grants"]) > 512:
        raise ScenarioError("scenario exceeds bounded metadata limits")
    offer_fields = {
        "node_id", "owner_id", "model_id", "usable", "quality_tier",
        "est_cost_units", "est_latency_ms", "est_energy_mwh",
        "free_memory_mib", "required_memory_mib",
    }
    seen_offers: set[tuple[str, str]] = set()
    for i, item in enumerate(source["offers"]):
        offer = _object(item, f"offers[{i}]")
        if set(offer) != offer_fields:
            raise ScenarioError(f"offers[{i}] fields do not match v0.1 schema")
        for key in ("node_id", "owner_id", "model_id"):
            _string(offer[key], key)
        _boolean(offer["usable"], "usable")
        quality = _integer(offer["quality_tier"], "quality_tier")
        if quality > 3:
            raise ScenarioError("quality_tier must be 0..3")
        for key in ("est_cost_units", "est_latency_ms", "est_energy_mwh", "free_memory_mib", "required_memory_mib"):
            _integer(offer[key], key)
        identity = (offer["node_id"], offer["model_id"])
        if identity in seen_offers:
            raise ScenarioError("duplicate node/model offer")
        seen_offers.add(identity)
    grant_fields = {
        "grant_id", "owner_id", "grantee_id", "node_id", "model_id",
        "expires_at", "allowed_data_classes", "max_cost_units", "revoked",
    }
    seen_grants: set[str] = set()
    for i, item in enumerate(source["grants"]):
        grant = _object(item, f"grants[{i}]")
        if set(grant) != grant_fields:
            raise ScenarioError(f"grants[{i}] fields do not match v0.1 schema")
        for key in ("grant_id", "owner_id", "grantee_id", "node_id", "model_id"):
            _string(grant[key], key)
        if grant["grant_id"] in seen_grants:
            raise ScenarioError("duplicate grant_id")
        seen_grants.add(grant["grant_id"])
        _time(grant["expires_at"])
        _integer(grant["max_cost_units"], "max_cost_units")
        _boolean(grant["revoked"], "revoked")
        classes = grant["allowed_data_classes"]
        if not isinstance(classes, list) or not classes or any(not isinstance(x, str) or x not in REMOTE_CLASSES for x in classes):
            raise ScenarioError("grant data classes must be a nonempty subset of PUBLIC/SYNTHETIC")
        if len(set(classes)) != len(classes):
            raise ScenarioError("duplicate grant data class")
    return source


def _grant_for(req: dict[str, Any], offer: dict[str, Any], grants: list[dict[str, Any]], now: datetime) -> str | None:
    matched = []
    for grant in grants:
        if (not grant["revoked"]
            and grant["owner_id"] == offer["owner_id"]
            and grant["grantee_id"] == req["requester_id"]
            and grant["node_id"] == offer["node_id"]
            and grant["model_id"] == offer["model_id"]
            and req["data_class"] in grant["allowed_data_classes"]
            and offer["est_cost_units"] <= grant["max_cost_units"]
            and now < _time(grant["expires_at"])):
            matched.append(grant["grant_id"])
    return min(matched) if matched else None


def evaluate(payload: Any, *, now: datetime | None = None) -> dict[str, Any]:
    """Local-first, cheapest eligible route; peer grants are metadata, never execution permission."""
    scenario = load_scenario(payload)
    if now is None:
        now = datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ScenarioError("evaluation clock must be timezone aware")
    now = now.astimezone(timezone.utc)
    req = scenario["request"]
    eligible_local = []
    eligible_remote = []
    rejected: dict[str, str] = {}
    for offer in sorted(scenario["offers"], key=lambda o: (o["node_id"], o["model_id"])):
        key = f'{offer["node_id"]}/{offer["model_id"]}'
        local = offer["owner_id"] == req["requester_id"]
        reason = None
        grant_id = None
        if not offer["usable"]:
            reason = "UNAVAILABLE"
        elif offer["required_memory_mib"] > offer["free_memory_mib"]:
            reason = "INSUFFICIENT_MEMORY"
        elif offer["quality_tier"] < req["min_quality_tier"]:
            reason = "QUALITY_TIER_TOO_LOW"
        elif offer["est_cost_units"] > req["max_cost_units"] or offer["est_latency_ms"] > req["max_latency_ms"] or offer["est_energy_mwh"] > req["max_energy_mwh"]:
            reason = "ESTIMATED_BUDGET_EXCEEDED"
        elif not local:
            if not req["allow_remote"]:
                reason = "REMOTE_DISABLED"
            elif req["data_class"] not in REMOTE_CLASSES:
                reason = "PRIVATE_DATA_LOCAL_ONLY"
            else:
                grant_id = _grant_for(req, offer, scenario["grants"], now)
                if grant_id is None:
                    reason = "NO_VALID_GRANT"
        if reason:
            rejected[key] = reason
        else:
            rank = (offer["est_cost_units"], offer["est_latency_ms"], offer["est_energy_mwh"], offer["node_id"], offer["model_id"])
            (eligible_local if local else eligible_remote).append((rank, offer, grant_id))

    candidates = eligible_local if eligible_local else eligible_remote
    if candidates:
        _, selected, grant_id = min(candidates, key=lambda x: x[0])
        result = {
            "status": "ROUTED", "mode": "LOCAL" if grant_id is None else "REMOTE",
            "reason": "LOCAL_FIRST" if grant_id is None else "GRANTED_REMOTE_FALLBACK",
            "node_id": selected["node_id"], "model_id": selected["model_id"],
            "grant_id": grant_id, "estimated_cost_units": selected["est_cost_units"],
        }
    else:
        result = {"status": "DENIED", "mode": None, "reason": "NO_ELIGIBLE_ROUTE", "node_id": None, "model_id": None, "grant_id": None, "estimated_cost_units": None}
    receipt = {
        "schema": "PORCHTALK_ROUTING_RECEIPT_V1", "request_id": req["request_id"],
        "evaluated_at": now.isoformat(), "decision": result,
        "rejected_offers": rejected,
        "warnings": ["OFFLINE_POLICY_SIMULATION_ONLY", "OFFER_CAPABILITIES_AND_ESTIMATES_ARE_UNVERIFIED", "SHA256_IS_NOT_A_SIGNATURE"],
    }
    canonical = json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    receipt["receipt_sha256"] = sha256(canonical.encode("utf-8")).hexdigest()
    return receipt
