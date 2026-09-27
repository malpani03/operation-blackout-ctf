import argparse
import base64
import sqlite3
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--encrypted-base64', action='store_true')
args = parser.parse_args()

db = Path(__file__).resolve().parents[2] / '.playwright-mcp-profile' / 'Default' / 'Network' / 'Cookies'
conn = sqlite3.connect(f'file:{db.as_posix()}?mode=ro', uri=True)
for row in conn.execute(
    "SELECT host_key, name, value, encrypted_value, expires_utc, path, is_secure, is_httponly "
    "FROM cookies WHERE host_key LIKE '%roshancodes%'"
):
    host, name, value, encrypted, expires, path, secure, httponly = row
    if args.encrypted_base64:
        print(base64.b64encode(encrypted).decode('ascii'))
    else:
        print(host, name, repr(value), len(encrypted), encrypted[:3].hex(), expires, path, secure, httponly)
