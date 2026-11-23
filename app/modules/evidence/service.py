import hashlib
import json

from .redaction import build_pack


def _section(snapshot, name):
    results = snapshot.get("results")
    section = results.get(name) if isinstance(results, dict) else None
    return section if isinstance(section, dict) else {}


def certify(snapshot):
    payload = json.dumps(snapshot, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()
    clock, ledger, intake = _section(snapshot, "clock"), _section(snapshot, "ledger"), _section(snapshot, "intake")
    can_settle = bool(ledger.get("complete") and not clock.get("missing")
                      and not ledger.get("differences") and clock.get("balanced"))
    return {"snapshot": snapshot, "integrity_sha256": hashlib.sha256(payload).hexdigest(),
            "can_settle": can_settle,
            "evidence_counts": {"intervals": len(clock.get("rows") or []), "tiers": len(ledger.get("rows") or []),
                                "isolated": len(intake.get("isolated") or [])}}


def issue_audit(snapshot):
    """Issue the externally shareable pack, reusing the internal conclusion."""
    internal = certify(snapshot)
    conclusion = {"can_settle": internal["can_settle"], "evidence_counts": internal["evidence_counts"],
                  "archive_sha256": internal["integrity_sha256"]}
    return build_pack(snapshot, conclusion)
