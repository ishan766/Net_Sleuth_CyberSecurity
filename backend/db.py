import json
import sqlite3
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from .config import DB_PATH

SCHEMA = '''
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS captures (id TEXT PRIMARY KEY, name TEXT NOT NULL, sample INTEGER NOT NULL DEFAULT 0, sha256 TEXT NOT NULL, file_size INTEGER NOT NULL, created_at TEXT NOT NULL, status TEXT NOT NULL, error TEXT, packet_count INTEGER NOT NULL DEFAULT 0, captured_bytes INTEGER NOT NULL DEFAULT 0, start_time TEXT, end_time TEXT, duration_seconds REAL NOT NULL DEFAULT 0, analysis_ms INTEGER);
CREATE TABLE IF NOT EXISTS packets (id INTEGER PRIMARY KEY, capture_id TEXT NOT NULL REFERENCES captures(id) ON DELETE CASCADE, number INTEGER NOT NULL, timestamp TEXT NOT NULL, captured_len INTEGER NOT NULL, wire_len INTEGER NOT NULL, protocol TEXT NOT NULL, layers TEXT NOT NULL, src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER, tcp_flags TEXT, dns_query TEXT, UNIQUE(capture_id,number));
CREATE INDEX IF NOT EXISTS ix_packets_capture_time ON packets(capture_id,timestamp);
CREATE INDEX IF NOT EXISTS ix_packets_capture_protocol ON packets(capture_id,protocol);
CREATE INDEX IF NOT EXISTS ix_packets_capture_ips ON packets(capture_id,src_ip,dst_ip);
CREATE TABLE IF NOT EXISTS conversations (id INTEGER PRIMARY KEY, capture_id TEXT NOT NULL REFERENCES captures(id) ON DELETE CASCADE, protocol TEXT NOT NULL, endpoint_a TEXT NOT NULL, endpoint_b TEXT NOT NULL, packets INTEGER NOT NULL, bytes INTEGER NOT NULL, a_to_b INTEGER NOT NULL, b_to_a INTEGER NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, tcp_flags TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_flows_capture ON conversations(capture_id,packets DESC);
CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY, capture_id TEXT NOT NULL REFERENCES captures(id) ON DELETE CASCADE, rule TEXT NOT NULL, severity TEXT NOT NULL, source TEXT, destination TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, evidence TEXT NOT NULL, explanation TEXT NOT NULL, recommendation TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_alerts_capture ON alerts(capture_id,severity);
CREATE TABLE IF NOT EXISTS analysis_jobs (id INTEGER PRIMARY KEY, capture_id TEXT NOT NULL REFERENCES captures(id) ON DELETE CASCADE, started_at TEXT NOT NULL, finished_at TEXT, status TEXT NOT NULL, error TEXT);
'''
PACKET_FIELDS = ('number','timestamp','captured_len','wire_len','protocol','layers','src_ip','dst_ip','src_port','dst_port','tcp_flags','dns_query')


class DatabaseConnection(sqlite3.Connection):
    _context_depth = 0

    def __enter__(self):
        self._context_depth += 1
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._context_depth -= 1
        if self._context_depth > 0:
            return False
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


def connect(path: Path = DB_PATH):
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=30, factory=DatabaseConnection)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('PRAGMA journal_mode=WAL')
    db.executescript(SCHEMA)
    db.execute('INSERT INTO schema_version(version) SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM schema_version)')
    return db


def rows(cursor):
    return [dict(row) for row in cursor.fetchall()]


def endpoint(ip, port):
    return f'[{ip}]:{port}' if ip and ':' in ip and port is not None else f'{ip}:{port}' if port is not None else ip or 'unknown'


def build_flows(packets):
    flows = {}
    for packet in packets:
        a = endpoint(packet['src_ip'], packet['src_port'])
        b = endpoint(packet['dst_ip'], packet['dst_port'])
        left, right = sorted((a, b))
        key = (packet['protocol'], left, right)
        flow = flows.setdefault(key, dict(protocol=packet['protocol'], endpoint_a=left, endpoint_b=right,
                                          packets=0, bytes=0, a_to_b=0, b_to_a=0,
                                          first_seen=packet['timestamp'], last_seen=packet['timestamp'], tcp_flags=defaultdict(int)))
        flow['packets'] += 1
        flow['bytes'] += packet['captured_len']
        flow['a_to_b' if a == left else 'b_to_a'] += 1
        flow['first_seen'] = min(flow['first_seen'], packet['timestamp'])
        flow['last_seen'] = max(flow['last_seen'], packet['timestamp'])
        if packet['tcp_flags']:
            flow['tcp_flags'][packet['tcp_flags']] += 1
    for flow in flows.values():
        flow['tcp_flags'] = json.dumps(flow['tcp_flags'], sort_keys=True)
    return list(flows.values())


def import_capture(db, capture, packets, alerts, elapsed_ms):
    flows = build_flows(packets)
    timestamps = [p['timestamp'] for p in packets]
    start, end = (min(timestamps), max(timestamps)) if timestamps else (None, None)
    duration = (datetime.fromisoformat(end.replace('Z','+00:00')) - datetime.fromisoformat(start.replace('Z','+00:00'))).total_seconds() if start else 0
    with db:
        db.execute('INSERT INTO captures(id,name,sample,sha256,file_size,created_at,status,packet_count,captured_bytes,start_time,end_time,duration_seconds,analysis_ms) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
                   (capture['id'],capture['name'],int(capture['sample']),capture['sha256'],capture['file_size'],capture['created_at'],'complete',len(packets),sum(p['captured_len'] for p in packets),start,end,duration,elapsed_ms))
        db.execute('INSERT INTO analysis_jobs(capture_id,started_at,finished_at,status) VALUES (?,?,?,?)', (capture['id'],capture['created_at'],datetime.now(timezone.utc).isoformat(),'complete'))
        db.executemany('INSERT INTO packets(capture_id,'+','.join(PACKET_FIELDS)+') VALUES ('+','.join('?' for _ in range(len(PACKET_FIELDS)+1))+')',
                       [(capture['id'], *(p.get(k) for k in PACKET_FIELDS)) for p in packets])
        db.executemany('INSERT INTO conversations(capture_id,protocol,endpoint_a,endpoint_b,packets,bytes,a_to_b,b_to_a,first_seen,last_seen,tcp_flags) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                       [(capture['id'],*(flow[k] for k in ('protocol','endpoint_a','endpoint_b','packets','bytes','a_to_b','b_to_a','first_seen','last_seen','tcp_flags'))) for flow in flows])
        db.executemany('INSERT INTO alerts(capture_id,rule,severity,source,destination,first_seen,last_seen,evidence,explanation,recommendation) VALUES (?,?,?,?,?,?,?,?,?,?)',
                       [(capture['id'],*(alert[k] for k in ('rule','severity','source','destination','first_seen','last_seen','evidence','explanation','recommendation'))) for alert in alerts])
    return len(flows)
