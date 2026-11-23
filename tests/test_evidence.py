import hashlib
import io
import json


def certificate(client, sample):
    run_id = client.post('/api/runs', json={'sample': sample}).json['run_id']
    return client.get(f'/api/evidence/{run_id}').json


def test_dirty_withheld_certificate(client):
    pack = certificate(client, 'dirty')
    assert pack['can_settle'] is False
    assert pack['evidence_counts'] == {'intervals': 7, 'tiers': 2, 'isolated': 6}


def test_clean_certificate_settleable(client):
    assert certificate(client, 'clean')['can_settle'] is True


def test_integrity_digest_can_be_recomputed(client):
    pack = certificate(client, 'dirty')
    serialized = json.dumps(pack['snapshot'], sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()
    assert pack['integrity_sha256'] == hashlib.sha256(serialized).hexdigest()


def test_download_matches_review(client):
    pack = certificate(client, 'dirty')
    response = client.get('/api/export/' + pack['snapshot']['run_id'])
    assert response.json == pack and response.headers['Content-Disposition'].startswith('attachment;')


def test_evidence_has_actual_source_rows(client):
    pack = certificate(client, 'dirty')
    assert pack['snapshot']['results']['intake']['isolated'][0]['raw'][0] == 'E03'
    assert pack['snapshot']['results']['notice']['completion_line'] == 2


def test_missing_evidence_cannot_be_downloaded(client):
    reply = client.get('/api/export/missing')
    assert (reply.status_code, reply.json['code']) == (404, 'UNKNOWN_RUN')


def audit_pack(client, sample):
    run_id = client.post('/api/runs', json={'sample': sample}).json['run_id']
    response = client.get(f'/api/audit/{run_id}')
    assert response.headers['Content-Disposition'].startswith('attachment;')
    return run_id, response


def test_audit_pack_withholds_rates_and_amounts(client):
    run_id, response = audit_pack(client, 'dirty')
    text = response.get_data(as_text=True)
    for secret in ('"2.00"', '"4.00"', '"3.00"', '"5.00"', '"60.00"', '"95.00"', '"100.00"', '"155.00"', '"160.00"'):
        assert secret not in text
    pack = response.json
    terms = pack['snapshot']['results']['intake']['accepted']['terms']
    assert [row['rate1_usd_min'] for row in terms] == ['[已隐去]', '[已隐去]']
    assert terms[0]['raw'][7:] == ['[已隐去]', '[已隐去]']
    assert pack['snapshot']['results']['intake']['accepted']['invoice'][0]['usd'] == '[已隐去]'


def test_audit_pack_keeps_original_line_numbers(client):
    run_id, response = audit_pack(client, 'dirty')
    snapshot = response.json['snapshot']
    isolated = snapshot['results']['intake']['isolated']
    assert [(row['source'], row['line'], row['code']) for row in isolated] == [
        ('events', 7, 'EXACT_DUPLICATE'), ('events', 11, 'MISSING_SENTINEL'),
        ('events', 12, 'COLUMN_COUNT'), ('events', 13, 'KEY_CONFLICT'),
        ('events', 14, 'KEY_CONFLICT'), ('stops', 7, 'REVERSED_RANGE')]
    assert len(isolated[3]['raw']) == 4 and isolated[3]['raw'][:3] == ['E11', 'NOR', '2027-01-01T01:01Z']
    # Masked cells keep their column, so the row still lines up with the file.
    assert len(snapshot['results']['intake']['accepted']['terms'][0]['raw']) == 9
    assert snapshot['results']['notice']['term']['raw'][4:7] == ['30', '35', '20']
    assert snapshot['results']['notice']['completion_line'] == 2


def test_audit_conclusion_reuses_internal_accounting(client):
    run_id, response = audit_pack(client, 'dirty')
    internal = client.get(f'/api/evidence/{run_id}').json
    pack = response.json
    assert (pack['can_settle'], pack['evidence_counts']) == (internal['can_settle'], internal['evidence_counts'])
    assert pack['snapshot']['results']['clock'] == internal['snapshot']['results']['clock']
    assert pack['snapshot']['results']['ledger']['rows'][1]['code'] == 'TIER_DIFFERENCE'


def test_internal_archive_keeps_originals(client):
    run_id, _ = audit_pack(client, 'dirty')
    stored = client.get(f'/api/runs/{run_id}').json
    assert stored['results']['intake']['accepted']['terms'][0]['rate1_usd_min'] == '2.00'
    assert stored['results']['intake']['accepted']['invoice'][1]['usd'] == '95.00'


def test_audit_retry_is_byte_identical_and_verifiable(client):
    run_id, first = audit_pack(client, 'dirty')
    again = client.get(f'/api/audit/{run_id}')
    assert first.data == again.data
    verified = client.post('/api/audit/verify', json=first.json).json
    assert verified['valid'] is True and verified['run_id'] == run_id


def test_audit_verification_detects_tampering(client):
    _, response = audit_pack(client, 'dirty')
    pack = response.json
    assert client.post('/api/audit/verify', json=pack).json['valid'] is True
    pack['snapshot']['results']['ledger']['delta_usd'] = '0.00'
    assert client.post('/api/audit/verify', json=pack).json['valid'] is False
    unsigned = {k: v for k, v in response.json.items() if k != 'audit_sha256'}
    assert client.post('/api/audit/verify', json=unsigned).json['valid'] is False


def test_audit_verification_accepts_uploaded_file(client):
    _, response = audit_pack(client, 'clean')
    upload = {'file': (io.BytesIO(response.data), 'audit.json')}
    assert client.post('/api/audit/verify', data=upload, content_type='multipart/form-data').json['valid'] is True


def test_audit_pack_of_upgraded_snapshot_is_still_redacted(client, tmp_path, dirty):
    from time import perf_counter

    import sqlite3

    from app.manifest import snapshot
    from app.pipeline import evaluate

    legacy = snapshot(dirty, evaluate(dirty), perf_counter())
    # Older writers stored sorted JSON, so the row key order no longer matches
    # the file columns; issuing must fall back to inferring the columns.
    legacy = json.loads(json.dumps(legacy, sort_keys=True))
    legacy['run_id'] = 'f' * 64
    path = client.application.config['DATABASE']
    db = sqlite3.connect(path)
    db.execute('CREATE TABLE IF NOT EXISTS harbor_runs (id TEXT PRIMARY KEY, snapshot TEXT NOT NULL)')
    db.execute('INSERT OR IGNORE INTO harbor_runs VALUES (?, ?)', (legacy['run_id'], json.dumps(legacy, sort_keys=True)))
    db.commit()
    db.close()

    response = client.get(f"/api/audit/{legacy['run_id']}")
    assert response.status_code == 200
    pack = response.json
    assert pack['snapshot']['results']['intake']['accepted']['terms'][0]['raw'][7:] == ['[已隐去]', '[已隐去]']
    assert pack['snapshot']['results']['intake']['accepted']['invoice'][0]['raw'][2] == '[已隐去]'
    assert client.post('/api/audit/verify', json=pack).json['valid'] is True


def test_audit_pack_of_isolated_terms_row_masks_rates(client, dirty):
    dirty['terms'] += 'R2,2026-12-15T00:00Z,2027-03-01T00:00Z,20,30,35,20,7,9\n'
    reply = client.post('/api/runs', json={'sources': dirty})
    run_id = reply.json['run_id']
    pack = client.get(f'/api/audit/{run_id}').json
    conflicting = [row for row in pack['snapshot']['results']['intake']['isolated'] if row['source'] == 'terms']
    assert conflicting and all(row['raw'][7:] == ['[已隐去]', '[已隐去]'] for row in conflicting)
    assert '"7"' not in json.dumps(pack) and '"9"' not in json.dumps(pack)


def test_audit_missing_run_has_404(client):
    reply = client.get('/api/audit/missing')
    assert (reply.status_code, reply.json['code']) == (404, 'UNKNOWN_RUN')


def test_audit_masks_reordered_columns(client, dirty):
    dirty['terms'] = ('rate1_usd_min,rate2_usd_min,version,start,end,priority,wait_min,allow_min,tier1_min\n'
                      '2,4,R1,2026-10-01T00:00Z,2027-01-01T00:00Z,10,60,40,25\n'
                      '3,5,R2,2026-12-15T00:00Z,2027-03-01T00:00Z,20,30,35,20\n')
    dirty['invoice'] = 'usd,tier,minutes\n60,1,20\n95,2,19\n'
    reply = client.post('/api/runs', json={'sources': dirty})
    assert reply.status_code == 201
    pack = client.get(f"/api/audit/{reply.json['run_id']}").json
    terms = pack['snapshot']['results']['intake']['accepted']['terms']
    assert all(row['raw'][:2] == ['[已隐去]', '[已隐去]'] for row in terms)
    assert all(row['raw'][2:5] != ['[已隐去]'] * 3 for row in terms)
    invoices = pack['snapshot']['results']['intake']['accepted']['invoice']
    assert all(row['raw'][0] == '[已隐去]' and row['raw'][1:] != ['[已隐去]'] * 2 for row in invoices)


def test_internal_evidence_download_is_unchanged(client):
    run_id = client.post('/api/runs', json={'sample': 'dirty'}).json['run_id']
    legacy = client.get(f'/api/export/{run_id}')
    assert legacy.headers['Content-Disposition'] == f'attachment; filename="laytime-{run_id[:12]}.json"'
    assert legacy.json['snapshot']['results']['intake']['accepted']['terms'][0]['rate1_usd_min'] == '2.00'


def test_audit_self_verify_endpoint(client):
    run_id = client.post('/api/runs', json={'sample': 'dirty'}).json['run_id']
    result = client.get(f'/api/audit/{run_id}/verify').json
    assert (result['valid'], result['run_id']) == (True, run_id)
