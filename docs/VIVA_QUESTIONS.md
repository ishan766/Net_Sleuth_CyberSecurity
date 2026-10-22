# NetSleuth viva questions and answers

1. **What is a PCAP?** A file format containing packet records with timestamps, captured lengths, original lengths, and frame bytes.
2. **What is PCAPNG?** A newer block based capture format that can represent multiple interfaces and richer metadata.
3. **Why distinguish captured and wire length?** Snaplen may truncate saved bytes while the original frame was longer.
4. **What does Scapy do here?** It decodes offline packet layers and supplies fields for NetSleuth's metadata records.
5. **Does parsing require live packet capture drivers?** No. Offline file parsing works without a libpcap capture provider.
6. **Which TCP/IP layers are extracted?** Ethernet, IPv4/IPv6, TCP/UDP/ICMP, and DNS metadata when present.
7. **How are missing fields represented?** As SQL NULL and omitted XML elements; no value is invented.
8. **Why store packet numbers?** They provide a stable position within one capture for inspection and range export.
9. **What is the primary PCAP to XML result?** A well formed `<capture>` document containing selected `<packet>` metadata elements.
10. **How are XML special characters handled?** The serializer uses standard XML escaping and attribute quoting.
11. **Why omit raw payloads?** Payloads may contain secrets; metadata is enough for this project's analysis goals.
12. **How can XML correctness be demonstrated?** Export a bounded range and parse it back with `xml.etree.ElementTree`; the test does this.
13. **Which SQLite tables exist?** `captures`, `packets`, `conversations`, `alerts`, `analysis_jobs`, and `schema_version`.
14. **Why normalize captures and packets?** One capture row holds shared metadata while packet rows reference it, reducing duplication.
15. **What makes import atomic?** Inserts run in one SQLite transaction; a failure rolls back the inserted capture and child rows.
16. **How is SQL injection prevented?** Values use SQL placeholders; table and sort identifiers are fixed allowlists.
17. **Why add indexes?** They speed common capture scoped time, protocol, address, and alert queries.
18. **How are duplicate uploads handled?** SHA-256 plus file size checks return the existing capture rather than adding duplicate rows.
19. **What is a conversation key?** Protocol and the sorted pair of endpoint IP:port identifiers.
20. **Why include ports for TCP flows?** Many independent connections can share the same IP pair.
21. **How is direction preserved?** Counters record packets from endpoint A to B and B to A separately.
22. **How is ICMP grouped?** By protocol and IP endpoint pair because this model has no ICMP port field.
23. **What causes a port sweep finding?** At least eight distinct destination endpoints with TCP SYN packets from one source in a 60 second bucket by default.
24. **Does a SYN sweep prove an attack?** No. It can also reflect diagnostics or incomplete capture context.
25. **What is a false positive?** A benign pattern crossing a rule threshold, such as authorized service checks.
26. **What is a false negative?** Suspicious behavior that does not cross thresholds or is absent from the captured packets.
27. **How are DNS queries counted?** The parser records query names from DNS query packets; analytics groups stored values.
28. **What does server side pagination solve?** It avoids loading the entire packet table into the browser at once.
29. **What limits large capture performance today?** Parsed metadata is accumulated in memory before one transactional import.
30. **How do you verify database persistence?** Query SQLite directly or inspect the read only SQLite Explorer row counts after import.
31. **Why is the service bound to localhost?** It lacks authentication and is designed as a local workstation, not a public service.
32. **What does a PCAP alone not establish?** It may not prove connection success, intent, host identity, or compromise.
33. **What tests run end to end?** A backend integration test generates a real PCAP, uploads it through FastAPI, queries SQLite, and reparses XML.
34. **What report format is implemented?** Downloadable JSON with metadata, analytics, findings, methodology, and limitations; PDF is future work.
