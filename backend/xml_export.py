"""Incremental XML serialization of database rows, without packet payloads."""
from xml.sax.saxutils import escape, quoteattr


def xml_safe(value):
    """Replace characters forbidden by XML 1.0 before escaping text."""
    return ''.join(char if ord(char) in (9, 10, 13) or 0x20 <= ord(char) <= 0xD7FF or 0xE000 <= ord(char) <= 0xFFFD or 0x10000 <= ord(char) <= 0x10FFFF else '\uFFFD' for char in str(value))


def xml_stream(capture, packet_rows):
    attrs = {'id': capture['id'], 'name': capture['name'], 'packet_count': str(capture['packet_count'])}
    yield '<?xml version="1.0" encoding="UTF-8"?>\n'
    yield '<capture ' + ' '.join(f'{k}={quoteattr(xml_safe(v))}' for k,v in attrs.items()) + '>\n'
    for packet in packet_rows:
        yield '  <packet number="' + str(packet['number']) + '">\n'
        for key in ('timestamp','captured_len','wire_len','protocol','layers','src_ip','dst_ip','src_port','dst_port','tcp_flags','dns_query'):
            value = packet[key]
            if value is not None:
                yield f'    <{key}>{escape(xml_safe(value))}</{key}>\n'
        yield '  </packet>\n'
    yield '</capture>\n'
