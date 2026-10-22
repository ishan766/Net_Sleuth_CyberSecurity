import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.getenv('NETSLEUTH_DB', ROOT / 'data' / 'netsleuth.sqlite3'))
UPLOAD_DIR = Path(os.getenv('NETSLEUTH_UPLOADS', ROOT / 'data' / 'uploads'))
MAX_UPLOAD_BYTES = int(os.getenv('NETSLEUTH_MAX_UPLOAD_MB', '100')) * 1024 * 1024
CORS_ORIGIN = os.getenv('NETSLEUTH_CORS_ORIGIN', 'http://localhost:5173')
