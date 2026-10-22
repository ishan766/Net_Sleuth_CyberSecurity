# Five to seven minute live demonstration

1. **0:00–0:40 — Introduce the problem.** Open `http://127.0.0.1:5173`. Point out the honest empty state, local analysis engine, and ten functional navigation views.
2. **0:40–1:30 — Import.** Open Import Capture and press **Load sample capture**. Explain that the sample contains fictional reserved IP addresses and a simulated SYN sweep. The overview should show 45 packets and a sample label.
3. **1:30–2:20 — Packet inspection.** Open Packet Explorer. Filter to UDP; expect five packets. Open one row to show timestamp, lengths, IPs, ports, layers, and DNS query metadata. Mention absent values are shown as unavailable.
4. **2:20–3:10 — Analytics and flows.** Open Traffic Analytics for actual protocol and time charts. Open Conversations and show a bidirectional flow with separate `A → B` and `B → A` counts.
5. **3:10–4:00 — Threat finding.** Open Threat Findings. Show the port sweep rule's evidence, time window, and investigation recommendation. State that SYNs alone do not prove malicious intent.
6. **4:00–4:50 — PCAP to XML.** Open PCAP to XML, choose starting packet 2 and limit 3, download XML, and show the three `<packet>` elements. Mention escaping and omitted payloads.
7. **4:50–5:40 — PCAP to SQLite.** Open SQLite Explorer. Show row counts and inspect packets, conversations, alerts, and jobs. Explain transactional import and parameterized SQL.
8. **5:40–6:30 — Report and close.** Download the JSON report in Investigation Reports. Show capture details, findings, methodology, and limitations. Point to the README and test results.
