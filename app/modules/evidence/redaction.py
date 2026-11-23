"""Build the external-audit pack for an archived run.

Internal archives keep every original row verbatim.  The external-audit pack
keeps each row together with its physical line number so a reviewer can still
trace every isolation decision back to the source file, but replaces contract
rates and billed/expected amounts with a fixed mask.

Nothing new is stored for this: the pack is derived from the archived snapshot
on demand, so runs archived before this feature existed can be issued as well.
Because the derivation only reads the snapshot, issuing the same run twice
yields byte-identical content and the same verification result.
"""

import copy
import hashlib
import json
from decimal import Decimal, InvalidOperation

from app.modules.intake.contract import HEADERS
from app.modules.intake.values import minute_stamp

MASK = "[已隐去]"
FORMAT = "harbor-audit-1"
CANONICAL = {"sort_keys": True, "ensure_ascii": False, "separators": (",", ":")}
FIELDS = {source: tuple(HEADERS[source].split(",")) for source in HEADERS}
SENSITIVE_FIELDS = {"terms": ("rate1_usd_min", "rate2_usd_min"), "invoice": ("usd",)}
META_KEYS = frozenset({"line", "raw", "key", "code", "source"})
TIME_FIELDS = frozenset({"time", "start", "end"})
INT_FIELDS = frozenset({"priority", "wait_min", "allow_min", "tier1_min", "tier", "minutes"})
MONEY_FIELDS = frozenset({"rate1_usd_min", "rate2_usd_min", "usd"})


def canonical_bytes(value):
    return json.dumps(value, **CANONICAL).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def is_secret_key(key):
    return key == "usd" or key.endswith("_usd") or key.endswith("_usd_min")


def _matches(field, raw, value):
    if value is None:
        return False
    text = str(raw).strip()
    try:
        if field in TIME_FIELDS:
            return minute_stamp(text) == minute_stamp(str(value).strip())
        if field in INT_FIELDS:
            return int(text) == int(value)
        if field in MONEY_FIELDS:
            return Decimal(text) == Decimal(str(value))
    except (ValueError, TypeError, InvalidOperation, ArithmeticError):
        return False
    return text == str(value)


def _perfect_matching(candidates, forced=None):
    size = len(candidates)
    used = set()
    if forced is not None:
        position, field = forced
        if field not in candidates[position]:
            return False
        used.add(field)
        remaining = [index for index in range(size) if index != position]
    else:
        remaining = list(range(size))
    remaining.sort(key=lambda index: (len(candidates[index]), index))

    def place(index):
        if index == len(remaining):
            return True
        position = remaining[index]
        for field in sorted(candidates[position]):
            if field in used:
                continue
            used.add(field)
            if place(index + 1):
                return True
            used.remove(field)
        return False

    return place(0)


def _key_order(source, accepted):
    """Recover column positions from the insertion order of the archived row.

    ``accept`` builds each row from the file header, so a snapshot written by
    this application preserves the original column order.  The order is only
    trusted when it is a permutation of the contract fields and every archived
    value fits its claimed column; otherwise the caller falls back to
    value-based inference (e.g. snapshots re-serialized with sorted keys).
    """
    if not accepted:
        return None
    fields = set(FIELDS[source])
    order = None
    for row in accepted:
        keys = tuple(key for key in row if key not in META_KEYS)
        if len(keys) != len(fields) or set(keys) != fields:
            return None
        if order is None:
            order = keys
        elif keys != order:
            return None
    for row in accepted:
        for position, field in enumerate(order):
            raw = row.get("raw")
            if not isinstance(raw, list) or len(raw) != len(order):
                return None
            if not _matches(field, raw[position], row.get(field)):
                return None
    return order


def _inferred_positions(source, accepted):
    fields = FIELDS[source]
    wanted = set(SENSITIVE_FIELDS.get(source, ()))
    rows = [row for row in accepted
            if isinstance(row, dict) and isinstance(row.get("raw"), list) and len(row["raw"]) == len(fields)]
    if not rows or len(rows) != len(accepted):
        return None
    candidates = []
    for position in range(len(fields)):
        options = set(fields)
        for row in rows:
            options = {field for field in options if _matches(field, row["raw"][position], row.get(field))}
            if not options:
                return None
        candidates.append(options)
    if not _perfect_matching(candidates):
        return None
    found = {position for position in range(len(fields))
             if any(_perfect_matching(candidates, (position, field)) for field in candidates[position] & wanted)}
    # A column that could hold a rate under some consistent layout is withheld
    # even if another layout would leave it visible.
    return frozenset(found) if found else None


def sensitive_positions(source, accepted):
    """Column positions of rates / billed amounts for one source.

    ``None`` means the layout could not be established; the caller then masks
    every cell of that source so a rate cannot slip through inside ``raw``.
    """
    try:
        rows = [row for row in accepted or [] if isinstance(row, dict)]
    except TypeError:
        return None
    wanted = set(SENSITIVE_FIELDS.get(source, ()))
    if not wanted:
        return frozenset()
    if not rows:
        # No accepted row means no trustworthy layout; withhold every cell so a
        # rate in an isolated row cannot slip through.
        return None
    order = _key_order(source, rows)
    if order is not None:
        return frozenset(index for index, field in enumerate(order) if field in wanted)
    return _inferred_positions(source, rows)


def _mask_raw(raw, positions, width):
    if not isinstance(raw, list):
        return MASK
    if positions is None:
        return [MASK for _ in raw]
    # Rows whose column count does not match the header may have been shifted
    # by the malformed column, so their layout is unknown: mask everything.
    if len(raw) != width:
        return [MASK for _ in raw]
    return [MASK if position in positions else value for position, value in enumerate(raw)]


def _scrub(node):
    if isinstance(node, dict):
        return {key: MASK if is_secret_key(key) and value is not None else _scrub(value)
                for key, value in node.items()}
    if isinstance(node, list):
        return [_scrub(value) for value in node]
    return node


def _dict(value):
    return value if isinstance(value, dict) else {}


def _list(value):
    return value if isinstance(value, list) else []


def redact_snapshot(snapshot):
    redacted = _scrub(copy.deepcopy(snapshot))
    original_intake = _dict(_dict(snapshot.get("results")).get("intake"))
    audit_intake = _dict(_dict(redacted.get("results")).get("intake"))
    accepted = _dict(original_intake.get("accepted"))
    positions = {source: sensitive_positions(source, _list(accepted.get(source)))
                 for source in SENSITIVE_FIELDS}
    for source, rows in _dict(audit_intake.get("accepted")).items():
        if source not in positions:
            continue
        for row in _list(rows):
            if isinstance(row, dict) and "raw" in row:
                row["raw"] = _mask_raw(row["raw"], positions[source], len(FIELDS[source]))
    for row in _list(audit_intake.get("isolated")):
        source = row.get("source") if isinstance(row, dict) else None
        if source in positions and "raw" in row:
            row["raw"] = _mask_raw(row["raw"], positions[source], len(FIELDS[source]))
    term = _dict(_dict(redacted.get("results")).get("notice")).get("term")
    if isinstance(term, dict) and "raw" in term:
        term["raw"] = _mask_raw(term["raw"], positions["terms"], len(FIELDS["terms"]))
    return redacted


def build_pack(snapshot, conclusion):
    redacted = redact_snapshot(snapshot)
    pack = {
        "format": FORMAT,
        "snapshot": redacted,
        "integrity_sha256": digest(redacted),
        "archive_sha256": conclusion["archive_sha256"],
        "can_settle": conclusion["can_settle"],
        "evidence_counts": conclusion["evidence_counts"],
        "redaction": {
            "policy": "withhold-contract-rate-and-billed-amount",
            "mask": MASK,
            "line_numbers": "preserved",
            "sources": {source: list(SENSITIVE_FIELDS[source]) for source in sorted(SENSITIVE_FIELDS)},
        },
        "verification": {
            "algorithm": "sha256",
            "canonical": "json-sort-keys/utf-8/compact",
            "integrity_sha256": "digest of snapshot",
            "audit_sha256": "digest of this document without audit_sha256",
        },
    }
    pack["audit_sha256"] = digest(pack)
    return pack


def verify(pack):
    if not isinstance(pack, dict):
        return {"valid": False, "code": "AUDIT_PACK_REQUIRED"}
    snapshot = pack.get("snapshot")
    integrity_ok = isinstance(snapshot, dict) and pack.get("integrity_sha256") == digest(snapshot)
    body = {key: value for key, value in pack.items() if key != "audit_sha256"}
    audit_ok = pack.get("audit_sha256") == digest(body)
    return {
        "valid": bool(integrity_ok and audit_ok),
        "format": pack.get("format"),
        "run_id": snapshot.get("run_id") if isinstance(snapshot, dict) else pack.get("run_id"),
        "integrity_sha256": {"expected": pack.get("integrity_sha256"),
                             "recomputed": digest(snapshot) if isinstance(snapshot, dict) else None,
                             "valid": bool(integrity_ok)},
        "audit_sha256": {"expected": pack.get("audit_sha256"), "recomputed": digest(body),
                         "valid": bool(audit_ok)},
    }
