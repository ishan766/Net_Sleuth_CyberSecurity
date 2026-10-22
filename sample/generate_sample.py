"""Generate a deterministic, entirely synthetic capture with reserved addresses."""
from pathlib import Path
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, ICMP, wrpcap

ROOT = Path(__file__).resolve().parent


def make_packets():
    packets = []
    base = 1761134400.0
    source = '192.0.2.10'
    target = '198.51.100.20'
    for index in range(20):
        packet = Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')/IP(src=source,dst=target)/TCP(sport=50000+index,dport=443,flags='S' if index%2==0 else 'A')
        packet.time = base + index*.5
        packets.append(packet)
    for index in range(10):
        packet = Ether(src='02:00:00:00:00:02',dst='02:00:00:00:00:01')/IP(src=target,dst=source)/TCP(sport=443,dport=50000+index,flags='SA')
        packet.time = base + 10 + index*.5
        packets.append(packet)
    for index in range(5):
        packet = Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:53')/IP(src=source,dst='192.0.2.53')/UDP(sport=53000+index,dport=53)/DNS(rd=1,qd=DNSQR(qname='example.test'))
        packet.time = base + 16 + index
        packets.append(packet)
    for index in range(9):
        packet = Ether(src='02:00:00:00:00:25',dst='02:00:00:00:00:02')/IP(src='203.0.113.25',dst=target)/TCP(sport=41000+index,dport=1000+index,flags='S')
        packet.time = base + 22 + index
        packets.append(packet)
    packet = Ether(src='02:00:00:00:00:02',dst='02:00:00:00:00:01')/IP(src=target,dst=source)/ICMP()
    packet.time = base + 35
    packets.append(packet)
    return packets


if __name__ == '__main__':
    ROOT.mkdir(exist_ok=True)
    path = ROOT / 'netsleuth-synthetic.pcap'
    wrpcap(str(path), make_packets())
    print(f'Wrote {path} with {len(make_packets())} synthetic packets')
