"""Bounded-memory metadata extraction. Payload bytes are never persisted."""
from datetime import datetime, timezone
from pathlib import Path
from scapy.all import PcapReader, Ether, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR


def iso_time(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def parse_capture(path: Path):
    with PcapReader(str(path)) as reader:
        for number, frame in enumerate(reader, 1):
            layers = []
            if Ether in frame:
                layers.append('Ethernet')
            network = frame[IP] if IP in frame else frame[IPv6] if IPv6 in frame else None
            if network is not None:
                layers.append('IPv4' if IP in frame else 'IPv6')
            transport = frame[TCP] if TCP in frame else frame[UDP] if UDP in frame else frame[ICMP] if ICMP in frame else None
            protocol = 'TCP' if TCP in frame else 'UDP' if UDP in frame else 'ICMP' if ICMP in frame else ('IPv6' if IPv6 in frame else 'IPv4' if IP in frame else 'OTHER')
            if transport is not None:
                layers.append(protocol)
            dns_name = None
            if DNS in frame:
                layers.append('DNS')
                if DNSQR in frame and frame[DNS].qr == 0:
                    dns_name = bytes(frame[DNSQR].qname).decode('utf-8', 'replace').rstrip('.')[:255]
            captured = len(bytes(frame))
            wire = getattr(frame, 'wirelen', None)
            yield dict(number=number, timestamp=iso_time(float(frame.time)), captured_len=captured,
                       wire_len=int(wire) if wire is not None else captured,
                       protocol=protocol, layers='/'.join(layers) or 'OTHER',
                       src_ip=network.src if network is not None else None,
                       dst_ip=network.dst if network is not None else None,
                       src_port=int(transport.sport) if TCP in frame or UDP in frame else None,
                       dst_port=int(transport.dport) if TCP in frame or UDP in frame else None,
                       tcp_flags=str(frame[TCP].flags) if TCP in frame else None,
                       dns_query=dns_name)
