import io
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
os.environ['NETSLEUTH_DB'] = str(ROOT/'data'/'test.sqlite3')
os.environ['NETSLEUTH_UPLOADS'] = str(ROOT/'data'/'test_uploads')

from fastapi.testclient import TestClient
from scapy.all import Ether, IP, TCP, UDP, PcapNgWriter, wrpcap
from backend.main import app
from backend.db import connect, build_flows
from backend.detection import detect
from backend.parser import parse_capture
from backend.xml_export import xml_stream
from sample.generate_sample import make_packets


def test_real_pipeline(tmp_path):
    path = tmp_path/'sample.pcap'
    wrpcap(str(path),make_packets())
    parsed = list(parse_capture(path))
    assert len(parsed) == 45
    assert {'TCP','UDP','ICMP'} <= {p['protocol'] for p in parsed}
    assert len(build_flows(parsed)) > 0
    findings = detect(parsed)
    assert any(a['rule']=='PORT_SWEEP' for a in findings)
    assert all(a['rule']!='DNS_BURST' for a in findings)
    client = TestClient(app)
    response = client.post('/api/captures',files={'file':('sample.pcap',path.read_bytes(),'application/octet-stream')})
    assert response.status_code in (200,201),response.text
    capture_id = response.json()['id']
    with connect() as db:
        assert db.execute('SELECT COUNT(*) FROM packets WHERE capture_id=?',(capture_id,)).fetchone()[0] == 45
        assert db.execute('SELECT COUNT(*) FROM conversations WHERE capture_id=?',(capture_id,)).fetchone()[0] > 0
    page = client.get(f'/api/captures/{capture_id}/packets?page_size=5&protocol=UDP').json()
    assert page['total']==5 and len(page['items'])==5
    xml = client.get(f'/api/captures/{capture_id}/export.xml?start=2&limit=3')
    assert xml.status_code==200
    assert len(ET.fromstring(xml.content).findall('packet'))==3
    assert client.get(f'/api/captures/{capture_id}/analytics').json()['capture']['packet_count']==45
    assert client.get('/api/database').json()['tables'][1]['rows']>=45
    assert client.get(f'/api/captures/{capture_id}/report.json').status_code==200


def test_validation_and_missing_fields(tmp_path):
    client=TestClient(app)
    assert client.post('/api/captures',files={'file':('bad.pcap',b'broken')}).status_code==422
    assert client.post('/api/captures',files={'file':('bad.txt',b'broken')}).status_code==415
    assert client.get('/api/captures/nonexistent/packets').status_code==404
    assert client.get('/api/captures/nonexistent/packets?page_size=1000').status_code==422
    path=tmp_path/'missing.pcap'
    wrpcap(str(path),[Ether()/IP(src='192.0.2.1',dst='192.0.2.2')])
    parsed=list(parse_capture(path))
    assert parsed[0]['src_port'] is None and parsed[0]['dst_port'] is None


def test_directional_flow_and_rule_negative():
    packet={'number':1,'timestamp':'2026-10-22T00:00:00.000000Z','captured_len':60,'wire_len':60,'protocol':'TCP','layers':'IPv4/TCP','src_ip':'192.0.2.1','dst_ip':'198.51.100.2','src_port':1234,'dst_port':80,'tcp_flags':'S','dns_query':None}
    reverse={**packet,'number':2,'src_ip':packet['dst_ip'],'dst_ip':packet['src_ip'],'src_port':80,'dst_port':1234,'tcp_flags':'SA'}
    flows=build_flows([packet,reverse])
    assert len(flows)==1 and flows[0]['a_to_b']==1 and flows[0]['b_to_a']==1
    assert detect([packet,reverse])==[]


def test_pcapng_and_empty_capture(tmp_path):
    path=tmp_path/'sample.pcapng'
    with PcapNgWriter(str(path)) as writer:
        writer.write(make_packets()[0])
    parsed=list(parse_capture(path))
    assert len(parsed)==1 and parsed[0]['protocol']=='TCP'
    client=TestClient(app)
    response=client.post('/api/captures',files={'file':('sample.pcapng',path.read_bytes())})
    assert response.status_code in (200,201),response.text
    empty=tmp_path/'empty.pcap'
    empty.write_bytes(bytes.fromhex('d4c3b2a1020004000000000000000000000004000001000000'))
    response=client.post('/api/captures',files={'file':('empty.pcap',empty.read_bytes())})
    assert response.status_code in (200,201),response.text
    capture_id=response.json()['id']
    assert client.get(f'/api/captures/{capture_id}').json()['packet_count']==0
    assert len(ET.fromstring(client.get(f'/api/captures/{capture_id}/export.xml').content).findall('packet'))==0


def test_sample_endpoint_is_labeled():
    client=TestClient(app)
    response=client.post('/api/sample')
    assert response.status_code in (200,201),response.text
    capture_id=response.json()['id']
    assert client.get(f'/api/captures/{capture_id}').json()['sample']==1


def test_upload_limit_and_filter_parameterization(monkeypatch):
    import backend.main as main
    client=TestClient(app)
    sample_id=client.post('/api/sample').json()['id']
    monkeypatch.setattr(main,'MAX_UPLOAD_BYTES',32)
    response=client.post('/api/captures',files={'file':('oversize.pcap',b'X'*40)})
    assert response.status_code==413
    filtered=client.get(f'/api/captures/{sample_id}/packets',params={'src_ip':"' OR 1=1 --"}).json()
    assert filtered['total']==0


def test_xml_escapes_untrusted_metadata():
    packet={'number':1,'timestamp':'2026-10-22T00:00:00Z','captured_len':1,'wire_len':1,'protocol':'OTHER','layers':'OTHER','src_ip':None,'dst_ip':None,'src_port':None,'dst_port':None,'tcp_flags':None,'dns_query':'a<&\x01'}
    content=''.join(xml_stream({'id':'one','name':'a&b.pcap','packet_count':1},[packet]))
    root=ET.fromstring(content)
    assert root.attrib['name']=='a&b.pcap'
    assert root.find('packet/dns_query').text=='a<&\ufffd'
