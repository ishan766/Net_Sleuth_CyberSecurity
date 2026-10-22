"""Conservative, explainable heuristics over capture metadata."""
from collections import defaultdict
from datetime import datetime

DEFAULT_THRESHOLDS = {'port_scan_ports': 8, 'fanout_hosts': 12, 'dns_queries': 30, 'window_seconds': 60}


def detect(packets, thresholds=None):
    cfg = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
    windows = defaultdict(list)
    for packet in packets:
        if not packet['src_ip']:
            continue
        second = int(datetime.fromisoformat(packet['timestamp'].replace('Z', '+00:00')).timestamp())
        bucket = second // cfg['window_seconds']
        windows[(packet['src_ip'], bucket)].append(packet)
    alerts = []
    for (source, _), group in windows.items():
        ordered = sorted(group, key=lambda item: item['timestamp'])
        first, last = ordered[0]['timestamp'], ordered[-1]['timestamp']
        syn = [p for p in group if p['protocol'] == 'TCP' and p['tcp_flags'] == 'S']
        ports = {(p['dst_ip'], p['dst_port']) for p in syn if p['dst_port'] is not None}
        hosts = {p['dst_ip'] for p in group if p['dst_ip']}
        queries = [p for p in group if p['dns_query']]
        specs = [
            ('PORT_SWEEP', len(ports), cfg['port_scan_ports'], 'warning', 'distinct destination TCP SYN endpoints', 'Check whether the destinations expected the probes and whether responses exist.'),
            ('HOST_FANOUT', len(hosts), cfg['fanout_hosts'], 'warning', 'distinct destination IP addresses', 'Compare against normal discovery or service behavior for this source.'),
            ('DNS_BURST', len(queries), cfg['dns_queries'], 'info', 'DNS queries', 'Review query names and resolver behavior; high volume alone is not malicious.'),
        ]
        for rule, observed, threshold, severity, unit, advice in specs:
            if observed >= threshold:
                alerts.append(dict(rule=rule, severity=severity, source=source, destination=None,
                                   first_seen=first, last_seen=last, evidence=f'{observed} {unit} in a {cfg["window_seconds"]} second window (threshold {threshold}).',
                                   explanation=f'{rule.replace("_", " ").title()} is a heuristic; this capture does not prove malicious intent or connection success.',
                                   recommendation=advice))
    return alerts
