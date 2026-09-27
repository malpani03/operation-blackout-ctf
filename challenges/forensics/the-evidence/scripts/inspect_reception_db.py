import sqlite3
from pathlib import Path

path = Path('analysis/reception-db/reception.db')
conn = sqlite3.connect(path)
for obj_type, name, sql in conn.execute(
    "SELECT type,name,sql FROM sqlite_master WHERE type IN ('table','view') ORDER BY name"
):
    print(f'\n{obj_type} {name}: {sql}')
    if obj_type != 'table' or name.startswith('sqlite_'):
        continue
    columns = [row[1] for row in conn.execute(f'PRAGMA table_info("{name}")')]
    count = conn.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]
    print(f'count={count} columns={columns}')
    for row in conn.execute(f'SELECT * FROM "{name}" ORDER BY rowid LIMIT 100'):
        values = []
        for value in row:
            if isinstance(value, bytes):
                values.append(f'<blob {len(value)} {value[:48].hex()}>')
            else:
                values.append(repr(value))
        print('  ' + ' | '.join(values))
