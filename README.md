# NetSleuth — PCAP Intelligence & Network Threat Analysis

NetSleuth is a local defensive network forensics workstation. It parses PCAP and PCAPNG captures with Scapy, stores packet metadata and analysis in SQLite, exports standards compliant XML, and presents real traffic charts, flows, and explainable rule findings in a React dashboard.

## Problem and objectives

Raw captures are difficult to inspect consistently. NetSleuth makes packet metadata queryable, preserves an investigation history, and gives students a reproducible demonstration of both **PCAP to XML** and **PCAP to SQLite**. It does not infer compromise from traffic alone.

## Architecture and features

The React/TypeScript/Vite frontend calls a FastAPI service. Scapy parses each uploaded capture; a transactional SQLite import stores captures, packets, conversations, alerts, and jobs. The API serves filtered pages and aggregated analytics. XML exports stream rows from the database. The included sample has 45 entirely synthetic packets using reserved documentation IP ranges.

Implemented screens: Overview, Import Capture, Packet Explorer, Conversations, Threat Findings, Traffic Analytics, PCAP to XML, SQLite Explorer, Investigation Reports, and Settings / About. Charts use API data. Report export is JSON.

## Windows setup

Prerequisites: Python 3.11+ and Node.js 20+. In PowerShell from this folder:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
cd frontend
npm install
cd ..
```

Generate or regenerate the deterministic sample:

```powershell
.\.venv\Scripts\python.exe sample\generate_sample.py
```

Start the backend in terminal 1:

```powershell
powershell -ExecutionPolicy Bypass -File .\start-backend.ps1
```

Start the frontend in terminal 2:

```powershell
powershell -ExecutionPolicy Bypass -File .\start-frontend.ps1
```

Open <http://127.0.0.1:5173>. API documentation: <http://127.0.0.1:8000/docs>. To change storage paths, upload limit, or allowed frontend origin, use the environment variable names in `.env.example` before starting the backend.

## Demonstrate the two academic modules

1. Open **Import capture** and press **Load sample capture**, or upload `sample/netsleuth-synthetic.pcap`.
2. Open **Packet explorer** and confirm 45 packets; filter to UDP to see five DNS queries.
3. Open **PCAP to XML**, set a starting packet and limit, download the XML, and open it in an XML viewer. The integration test also reparses it with Python's `ElementTree`.
4. Open **SQLite explorer** to see actual packet, conversation, alert, and job row counts. For direct proof, run:

```powershell
.\.venv\Scripts\python.exe -c "import sqlite3; db=sqlite3.connect('data/netsleuth.sqlite3'); print(db.execute('SELECT COUNT(*) FROM packets').fetchone()[0])"
```

5. Open **Traffic analytics**, **Conversations**, **Threat findings**, and **Investigation reports**. The sample's simulated SYN sweep should produce one evidence based port sweep finding.

## Testing

```powershell
.\.venv\Scripts\python.exe -m pytest -q
cd frontend
npm run build
```

The test suite uses a separate test database in `data/test.sqlite3`. See [TEST_RESULTS.md](docs/TEST_RESULTS.md) for executed results and environment notes.

## Retention, backup, and security

Uploaded capture files are stored under `data/uploads` to preserve the source. SQLite stores metadata, not packet payload bytes. Delete a capture in **Investigation reports** to remove its rows and uploaded file. Stop the service and copy `data/netsleuth.sqlite3` plus `data/uploads` to back up an investigation. The default service is for local use; it has no authentication and should not be exposed to an untrusted network. Only inspect captures you own or are authorized to examine. DNS names and IP addresses may be sensitive metadata.

## Troubleshooting

- If `python` is not on PATH, use the full path to your Python executable to create the virtual environment.
- If Scapy reports no libpcap provider, offline PCAP parsing still works; live capture is not used.
- If the browser cannot reach the API, confirm both terminal processes are running and the Vite proxy points to port 8000.
- `npm run dev` may fail in restricted Windows sandboxes while Vite prebundles dependencies. The verified `npm run build` then `npm run start` path serves the same UI and API proxy.
- If the sample button reports missing data, regenerate the sample with the command above.
- A malformed or unsupported capture returns an HTTP error and is not imported.

## Documentation

See [project report](docs/PROJECT_REPORT.md), [architecture](docs/ARCHITECTURE.md), [demo script](docs/DEMO_SCRIPT.md), [viva questions](docs/VIVA_QUESTIONS.md), [test results](docs/TEST_RESULTS.md), and [screenshot checklist](docs/SCREENSHOT_CHECKLIST.md).
