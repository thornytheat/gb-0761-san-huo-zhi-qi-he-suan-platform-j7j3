import json

from flask import Blueprint, current_app, jsonify, request

from app.errors import Rejected
from app.modules.runs.storage import lookup
from .redaction import verify
from .service import certify, issue_audit

bp = Blueprint("evidence", __name__)


def _pack(run_id):
    return issue_audit(lookup(current_app.config["DATABASE"], run_id))


def _attachment(pack, run_id):
    response = jsonify(pack)
    response.headers["Content-Disposition"] = f'attachment; filename="laytime-audit-{run_id[:12]}.json"'
    return response


@bp.get("/api/evidence/<run_id>")
def review(run_id):
    return certify(lookup(current_app.config["DATABASE"], run_id))


@bp.get("/api/evidence/<run_id>/audit")
def audit_review(run_id):
    return _pack(run_id)


@bp.get("/api/export/<run_id>/audit")
def audit_export(run_id):
    return _attachment(_pack(run_id), run_id)


@bp.get("/api/audit/<run_id>")
def audit_download(run_id):
    return _attachment(_pack(run_id), run_id)


@bp.get("/api/runs/<run_id>/audit")
def audit_run(run_id):
    return _attachment(_pack(run_id), run_id)


@bp.get("/api/audit/<run_id>/verify")
def audit_self_verify(run_id):
    return verify(_pack(run_id))


@bp.post("/api/audit/verify")
def audit_verify():
    payload = request.get_json(silent=True)
    if payload is None and "file" in request.files:
        try:
            payload = json.loads(request.files["file"].read())
        except (ValueError, UnicodeDecodeError):
            raise Rejected("INVALID_AUDIT_PACK", status=400) from None
    if not isinstance(payload, dict):
        raise Rejected("AUDIT_PACK_REQUIRED", status=400)
    return verify(payload)


@bp.get("/api/export/<run_id>")
def download(run_id):
    response = jsonify(review(run_id))
    response.headers["Content-Disposition"] = f'attachment; filename="laytime-{run_id[:12]}.json"'
    return response
