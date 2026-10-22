import hashlib
import io
import json
import os
import sqlite3
import time
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

from .config import CORS_ORIGIN, DB_PATH, MAX_UPLOAD_BYTES, UPLOAD_DIR
from .db import connect, import_capture, rows
from .detection import detect, DEFAULT_THRESHOLDS
from .parser import parse_capture
from .xml_export import xml_stream

app = FastAPI(title='NetSleuth API', version='1.0.0', description='Local defensive PCAP analysis API')
app.add_middleware(CORSMiddleware, allow_origins=[CORS_ORIGIN], allow_methods=['GET','POST','DELETE'], allow_headers=['*'])


def get_capture(db, capture_id):
    row = db.execute('SELECT * FROM captures WHERE id=?', (capture_id,)).fetchone()
    if not row:
        raise HTTPException(404, 'Capture not found')
    return dict(row)


def page_query(db, table, capture_id, page, page_size, where='', params=(), order='id ASC'):
    condition = 'capture_id=?' + (f' AND {where}' if where else '')
    args = (capture_id, *params)
    total = db.execute(f'SELECT COUNT(*) FROM {table} WHERE {condition}', args).fetchone()[0]
    items = rows(db.execute(f'SELECT * FROM {table} WHERE {condition} ORDER BY {order} LIMIT ? OFFSET ?', (*args,page_size,(page-1)*page_size)))
    return {'items':items,'total':total,'page':page,'page_size':page_size}


@app.get('/api/health')
def health():
    with connect() as db:
        db.execute('SELECT 1')
    return {'status':'ok','schema_version':1}


@app.post('/api/captures', status_code=201)
def upload_capture(file: UploadFile = File(...), sample: bool = False):
    name = Path(file.filename or '').name
    if not name.lower().endswith(('.pcap','.pcapng')):
        raise HTTPException(415, 'Upload a .pcap or .pcapng capture')
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    capture_id = uuid.uuid4().hex
    path = UPLOAD_DIR / f'{capture_id}{Path(name).suffix.lower()}'
    digest = hashlib.sha256()
    size = 0
    started = time.perf_counter()
    try:
        with path.open('wb') as target:
            while chunk := file.file.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    raise HTTPException(413, f'Capture exceeds {MAX_UPLOAD_BYTES // (1024*1024)} MiB limit')
                digest.update(chunk)
                target.write(chunk)
        if size < 24:
            raise HTTPException(422, 'Capture is empty or too short')
        magic = path.open('rb').read(4)
        if magic not in (b'\xd4\xc3\xb2\xa1',b'\xa1\xb2\xc3\xd4',b'\x4d\x3c\xb2\xa1',b'\xa1\xb2\x3c\x4d',b'\x0a\x0d\x0d\x0a'):
            raise HTTPException(422, 'Invalid PCAP or PCAPNG header')
        try:
            packets = list(parse_capture(path))
        except Exception as error:
            raise HTTPException(422, 'Capture could not be parsed; check that the file is valid') from error
        with connect() as db:
            existing = db.execute('SELECT id FROM captures WHERE sha256=? AND file_size=?', (digest.hexdigest(),size)).fetchone()
            if existing:
                if sample:
                    db.execute('UPDATE captures SET sample=1 WHERE id=?',(existing['id'],))
                path.unlink(missing_ok=True)
                return JSONResponse(status_code=200, content={'id':existing['id'],'duplicate':True})
            capture = {'id':capture_id,'name':name[:255],'sample':sample,'sha256':digest.hexdigest(),'file_size':size,'created_at':datetime.now(timezone.utc).isoformat()}
            alerts = detect(packets)
            import_capture(db,capture,packets,alerts,round((time.perf_counter()-started)*1000))
        return {'id':capture_id,'packet_count':len(packets),'alert_count':len(alerts),'duplicate':False}
    except Exception:
        path.unlink(missing_ok=True)
        raise


@app.post('/api/sample', status_code=201)
def load_sample():
    path = Path(__file__).resolve().parent.parent / 'sample' / 'netsleuth-synthetic.pcap'
    if not path.exists():
        raise HTTPException(404, 'Sample capture is missing; run sample/generate_sample.py')
    with path.open('rb') as source:
        return upload_capture(UploadFile(filename=path.name,file=source),sample=True)


@app.get('/api/captures')
def captures():
    with connect() as db:
        return rows(db.execute('SELECT * FROM captures ORDER BY created_at DESC'))


@app.get('/api/captures/{capture_id}')
def capture_detail(capture_id: str):
    with connect() as db:
        return get_capture(db,capture_id)


@app.delete('/api/captures/{capture_id}', status_code=204)
def delete_capture(capture_id: str):
    with connect() as db:
        capture = get_capture(db,capture_id)
        db.execute('DELETE FROM captures WHERE id=?',(capture_id,))
    (UPLOAD_DIR / f'{capture_id}{Path(capture["name"]).suffix.lower()}').unlink(missing_ok=True)


@app.get('/api/captures/{capture_id}/jobs')
def jobs(capture_id: str):
    with connect() as db:
        get_capture(db,capture_id)
        return rows(db.execute('SELECT * FROM analysis_jobs WHERE capture_id=? ORDER BY id DESC',(capture_id,)))


@app.get('/api/captures/{capture_id}/packets')
def packets(capture_id: str, page: int = Query(1,ge=1), page_size: int = Query(25,ge=1,le=200),
            protocol: str | None = None, src_ip: str | None = None, dst_ip: str | None = None,
            port: int | None = Query(None,ge=0,le=65535), search: str | None = Query(None,max_length=100),
            sort: Literal['number','timestamp','captured_len','protocol'] = 'number', direction: Literal['asc','desc'] = 'asc'):
    clauses, args = [], []
    for column, value in (('protocol',protocol),('src_ip',src_ip),('dst_ip',dst_ip)):
        if value:
            clauses.append(f'{column}=?'); args.append(value)
    if port is not None:
        clauses.append('(src_port=? OR dst_port=?)'); args += [port,port]
    if search:
        clauses.append('(src_ip LIKE ? OR dst_ip LIKE ? OR dns_query LIKE ?)'); args += [f'%{search}%']*3
    with connect() as db:
        get_capture(db,capture_id)
        return page_query(db,'packets',capture_id,page,page_size,' AND '.join(clauses),tuple(args),f'{sort} {direction.upper()}')


@app.get('/api/captures/{capture_id}/packets/{number}')
def packet_detail(capture_id: str, number: int):
    with connect() as db:
        get_capture(db,capture_id)
        row = db.execute('SELECT * FROM packets WHERE capture_id=? AND number=?',(capture_id,number)).fetchone()
        if not row: raise HTTPException(404,'Packet not found')
        return dict(row)


@app.get('/api/captures/{capture_id}/conversations')
def conversations(capture_id: str, page: int = Query(1,ge=1), page_size: int = Query(25,ge=1,le=200), protocol: str | None = None, sort: Literal['packets','bytes','first_seen'] = 'packets'):
    with connect() as db:
        get_capture(db,capture_id)
        result = page_query(db,'conversations',capture_id,page,page_size,'protocol=?' if protocol else '',(protocol,) if protocol else (),f'{sort} DESC')
        for item in result['items']:
            item['tcp_flags'] = json.loads(item['tcp_flags'])
        return result


@app.get('/api/captures/{capture_id}/alerts')
def alerts(capture_id: str, page: int = Query(1,ge=1), page_size: int = Query(25,ge=1,le=200), severity: str | None = None, rule: str | None = None):
    clauses, args = [], []
    if severity: clauses.append('severity=?'); args.append(severity)
    if rule: clauses.append('rule=?'); args.append(rule)
    with connect() as db:
        get_capture(db,capture_id)
        return page_query(db,'alerts',capture_id,page,page_size,' AND '.join(clauses),tuple(args),'first_seen DESC')


@app.get('/api/captures/{capture_id}/analytics')
def analytics(capture_id: str):
    with connect() as db:
        capture = get_capture(db,capture_id)
        protocol = rows(db.execute('SELECT protocol,COUNT(*) packets,SUM(captured_len) bytes FROM packets WHERE capture_id=? GROUP BY protocol ORDER BY packets DESC',(capture_id,)))
        timeline = rows(db.execute("SELECT substr(timestamp,1,19) bucket,COUNT(*) packets,SUM(captured_len) bytes FROM packets WHERE capture_id=? GROUP BY bucket ORDER BY bucket",(capture_id,)))
        sources = rows(db.execute('SELECT src_ip address,COUNT(*) packets FROM packets WHERE capture_id=? AND src_ip IS NOT NULL GROUP BY src_ip ORDER BY packets DESC LIMIT 10',(capture_id,)))
        destinations = rows(db.execute('SELECT dst_ip address,COUNT(*) packets FROM packets WHERE capture_id=? AND dst_ip IS NOT NULL GROUP BY dst_ip ORDER BY packets DESC LIMIT 10',(capture_id,)))
        ports = rows(db.execute('SELECT dst_port port,COUNT(*) packets FROM packets WHERE capture_id=? AND dst_port IS NOT NULL GROUP BY dst_port ORDER BY packets DESC LIMIT 10',(capture_id,)))
        dns = rows(db.execute('SELECT dns_query query,COUNT(*) packets FROM packets WHERE capture_id=? AND dns_query IS NOT NULL GROUP BY dns_query ORDER BY packets DESC LIMIT 10',(capture_id,)))
        counts = db.execute('SELECT COUNT(DISTINCT src_ip),COUNT(DISTINCT dst_ip) FROM packets WHERE capture_id=?',(capture_id,)).fetchone()
        alert_count = db.execute('SELECT COUNT(*) FROM alerts WHERE capture_id=?',(capture_id,)).fetchone()[0]
        flows = rows(db.execute('SELECT * FROM conversations WHERE capture_id=? ORDER BY packets DESC LIMIT 5',(capture_id,)))
        return {'capture':capture,'protocols':protocol,'timeline':timeline,'sources':sources,'destinations':destinations,'ports':ports,'dns':dns,'unique_sources':counts[0],'unique_destinations':counts[1],'alert_count':alert_count,'top_conversations':flows}


@app.get('/api/captures/{capture_id}/export.xml')
def export_xml(capture_id: str, start: int = Query(1,ge=1), limit: int = Query(10000,ge=1,le=100000)):
    with connect() as db:
        capture = get_capture(db,capture_id)
    def generate():
        with connect() as db:
            cursor = db.execute('SELECT * FROM packets WHERE capture_id=? AND number>=? ORDER BY number LIMIT ?',(capture_id,start,limit))
            yield from xml_stream(capture,cursor)
    return StreamingResponse(generate(),media_type='application/xml',headers={'Content-Disposition':f'attachment; filename="netsleuth-{capture_id[:12]}.xml"','X-Exported-Packets':str(max(0,min(limit,capture['packet_count']-start+1)))})


@app.get('/api/captures/{capture_id}/report.json')
def report(capture_id: str):
    data = analytics(capture_id)
    data['findings'] = alerts(capture_id,page=1,page_size=200)['items']
    data['generated_at'] = datetime.now(timezone.utc).isoformat()
    data['methodology'] = 'Metadata-only analysis; rule thresholds are documented in backend/detection.py.'
    data['limitations'] = 'A capture may omit packets. Heuristic findings do not establish malicious intent, successful connections, or compromise.'
    return JSONResponse(data,headers={'Content-Disposition':f'attachment; filename="netsleuth-{capture_id[:12]}-report.json"'})


@app.get('/api/database')
def database_stats():
    with connect() as db:
        tables = ['captures','packets','conversations','alerts','analysis_jobs']
        counts = [{'table':name,'rows':db.execute(f'SELECT COUNT(*) FROM {name}').fetchone()[0]} for name in tables]
        return {'schema_version':1,'tables':counts,'database_bytes':DB_PATH.stat().st_size if DB_PATH.exists() else 0}


@app.get('/api/database/{table}')
def database_rows(table: Literal['captures','packets','conversations','alerts','analysis_jobs'], page: int = Query(1,ge=1), page_size: int = Query(25,ge=1,le=100)):
    with connect() as db:
        total = db.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]
        return {'items':rows(db.execute(f'SELECT * FROM {table} ORDER BY rowid DESC LIMIT ? OFFSET ?',(page_size,(page-1)*page_size))),'total':total,'page':page,'page_size':page_size}
