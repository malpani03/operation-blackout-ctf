import datetime as dt
import sqlite3
from pathlib import Path


def iso_ns(value):
    sec, ns = divmod(value, 1_000_000_000)
    return dt.datetime.fromtimestamp(sec, dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S') + f'.{ns:09d}Z'


db = Path('assets/evidence-acquisition/historian.db')
conn = sqlite3.connect(f'file:{db.as_posix()}?mode=ro', uri=True)
print('RUNTIME EVENTS')
for row in conn.execute('SELECT id,event_time_ns,lane,code,detail FROM runtime_events ORDER BY event_time_ns,lane,id'):
    print(row[0], iso_ns(row[1]), 'lane', row[2], row[3], row[4])

print('\nASSET SUMMARIES')
for row in conn.execute('''
    SELECT asset_tag,COUNT(*),MIN(seq_no),MAX(seq_no),COUNT(DISTINCT seq_no),
           MIN(device_time_ns),MAX(device_time_ns),MIN(gateway_time_ns),MAX(gateway_time_ns),
           MIN(sensor_value),MAX(sensor_value),COUNT(DISTINCT quality)
    FROM samples GROUP BY asset_tag ORDER BY asset_tag
'''):
    print(row[:5], iso_ns(row[5]), iso_ns(row[6]), iso_ns(row[7]), iso_ns(row[8]), row[9:])

print('\nEARLIEST/LATEST PER ASSET BY DEVICE TIME')
assets = [r[0] for r in conn.execute('SELECT DISTINCT asset_tag FROM samples ORDER BY asset_tag')]
for asset in assets:
    print('\n', asset)
    rows = conn.execute('''
      SELECT seq_no,device_time_ns,gateway_time_ns,sensor_value,quality
      FROM samples WHERE asset_tag=? ORDER BY device_time_ns LIMIT 8
    ''', (asset,)).fetchall()
    rows += conn.execute('''
      SELECT seq_no,device_time_ns,gateway_time_ns,sensor_value,quality
      FROM samples WHERE asset_tag=? ORDER BY device_time_ns DESC LIMIT 8
    ''', (asset,)).fetchall()
    for seq, device, gateway, value, quality in rows:
        print(seq, iso_ns(device), iso_ns(gateway), repr(value), quality)
