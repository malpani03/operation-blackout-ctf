import json
import sqlite3
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DATA = json.loads((ROOT / "assets" / "epilogue-training.json").read_text(encoding="utf-8"))


def crc16(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def labels(name):
    if not isinstance(name, str):
        return None
    parts = name.split(".")
    if len(parts) < 6:
        return None
    payload, sequence, claimed, stream = parts[:4]
    domain = ".".join(parts[4:])
    try:
        raw = bytes.fromhex(payload)
        seq = int(sequence, 16)
        claim = int(claimed, 16)
    except (ValueError, TypeError):
        return None
    return raw, seq, claim, stream, domain


db = sqlite3.connect(ROOT / "analysis" / "epilogue-training.sqlite")
db.executescript("""
PRAGMA journal_mode=OFF;
DROP TABLE IF EXISTS dns;
DROP TABLE IF EXISTS leases;
DROP TABLE IF EXISTS assets;
DROP TABLE IF EXISTS clocks;
DROP TABLE IF EXISTS processes;
DROP TABLE IF EXISTS modules;
DROP TABLE IF EXISTS files;
DROP TABLE IF EXISTS certificates;
DROP TABLE IF EXISTS deployments;
DROP TABLE IF EXISTS changes;
DROP TABLE IF EXISTS labels;
CREATE TABLE dns(address TEXT, observed INTEGER, wire_name TEXT, qtype TEXT, sensor TEXT);
CREATE TABLE leases(address TEXT, mac TEXT, start INTEGER, end INTEGER);
CREATE TABLE assets(mac TEXT, host TEXT);
CREATE TABLE clocks(sensor TEXT, offset INTEGER);
CREATE TABLE processes(host TEXT, pid INTEGER, ppid INTEGER, local_time INTEGER, image_hash TEXT, sensor TEXT);
CREATE TABLE modules(host TEXT, pid INTEGER, local_time INTEGER, module_hash TEXT, sensor TEXT);
CREATE TABLE files(digest TEXT, signer TEXT);
CREATE TABLE certificates(subject TEXT, valid_from INTEGER, valid_to INTEGER, revoked_at INTEGER);
CREATE TABLE deployments(id TEXT, host TEXT, module_hash TEXT, start INTEGER, end INTEGER);
CREATE TABLE changes(deployment_id TEXT, sequence INTEGER, state TEXT);
CREATE TABLE labels(host TEXT, domain TEXT, malicious INTEGER);
""")
for name, rows in DATA["tables"].items():
    marks = ",".join("?" for _ in rows[0])
    db.executemany(f"INSERT INTO {name} VALUES ({marks})", rows)
db.executemany(
    "INSERT INTO labels VALUES (?,?,?)",
    [(x["host"], x["domain"], int(x["malicious"])) for x in DATA["labels"]],
)

db.create_function("nj_sequence", 1, lambda x: labels(x)[1] if labels(x) else None)
db.create_function("nj_payload", 1, lambda x: labels(x)[0].hex() if labels(x) else None)
db.create_function("nj_claimed_crc", 1, lambda x: labels(x)[2] if labels(x) else None)
db.create_function("nj_stream", 1, lambda x: labels(x)[3] if labels(x) else None)
db.create_function("nj_domain", 1, lambda x: labels(x)[4] if labels(x) else None)
db.create_function("nj_crc16", 1, lambda x: crc16(labels(x)[0]) if labels(x) else None)

query = r"""
WITH
dns_norm AS (
  SELECT d.*, d.observed-c.offset AS utc,
         nj_sequence(d.wire_name) AS seq,
         nj_payload(d.wire_name) AS payload,
         nj_claimed_crc(d.wire_name) AS claimed,
         nj_crc16(d.wire_name) AS actual,
         nj_stream(d.wire_name) AS stream,
         nj_domain(d.wire_name) AS domain
  FROM dns d JOIN clocks c USING(sensor)
  WHERE d.qtype='TXT'
),
mapped AS (
  SELECT dn.*, a.host
  FROM dns_norm dn
  JOIN leases l ON l.address=dn.address AND dn.utc BETWEEN l.start AND l.end
  JOIN assets a USING(mac)
),
chunks AS (
  SELECT host,domain,stream,seq,payload,MIN(utc) AS utc,
         MAX(actual=claimed) AS crc_ok,COUNT(*) AS deliveries
  FROM mapped WHERE stream IS NOT NULL
  GROUP BY host,domain,stream,seq,payload
),
streams AS (
  SELECT host,domain,stream,MIN(utc) first_utc,MAX(utc) last_utc,
         COUNT(*) chunks, COUNT(DISTINCT seq) seqs,
         MIN(seq) min_seq,MAX(seq) max_seq,
         SUM(crc_ok) good_chunks,SUM(deliveries) deliveries,
         COUNT(DISTINCT payload) payloads
  FROM chunks GROUP BY host,domain,stream
),
proc AS (
 SELECT p.*, p.local_time-c.offset AS utc,
        EXISTS(SELECT 1 FROM processes par WHERE par.host=p.host AND par.pid=p.ppid) has_parent
 FROM processes p JOIN clocks c USING(sensor)
),
mods AS (
 SELECT m.*,m.local_time-c.offset AS utc,f.signer,
   EXISTS(SELECT 1 FROM certificates cert
          WHERE cert.subject=f.signer AND (m.local_time-c.offset) BETWEEN cert.valid_from AND cert.valid_to
            AND (cert.revoked_at IS NULL OR cert.revoked_at > (m.local_time-c.offset))) AS trusted,
   EXISTS(SELECT 1 FROM deployments d
          WHERE d.host=m.host AND d.module_hash=m.module_hash AND (m.local_time-c.offset) BETWEEN d.start AND d.end
            AND (SELECT ch.state FROM changes ch WHERE ch.deployment_id=d.id ORDER BY ch.sequence DESC LIMIT 1)='approved') AS authorized
 FROM modules m JOIN clocks c USING(sensor) LEFT JOIN files f ON f.digest=m.module_hash
)
SELECT l.malicious,s.host,s.domain,s.stream,s.first_utc,s.last_utc,s.chunks,s.seqs,s.min_seq,s.max_seq,
       s.good_chunks,s.deliveries,
       (SELECT COUNT(*) FROM proc p WHERE p.host=s.host AND p.utc BETWEEN s.first_utc-600 AND s.last_utc+600) near_proc,
       (SELECT COUNT(*) FROM proc p WHERE p.host=s.host AND p.utc BETWEEN s.first_utc-600 AND s.last_utc+600 AND p.has_parent) parented_proc,
       (SELECT COUNT(*) FROM mods m WHERE m.host=s.host AND m.utc BETWEEN s.first_utc-600 AND s.last_utc+600) near_mod,
       (SELECT COUNT(*) FROM mods m WHERE m.host=s.host AND m.utc BETWEEN s.first_utc-600 AND s.last_utc+600 AND m.trusted) trusted_mod,
       (SELECT COUNT(*) FROM mods m WHERE m.host=s.host AND m.utc BETWEEN s.first_utc-600 AND s.last_utc+600 AND m.authorized) authorized_mod,
       (SELECT group_concat((m.utc-s.first_utc)||':'||m.trusted||':'||m.authorized||':'||m.pid) FROM mods m WHERE m.host=s.host AND m.utc BETWEEN s.first_utc-600 AND s.last_utc+600) mod_detail,
       (SELECT group_concat((p.utc-s.first_utc)||':'||p.has_parent||':'||p.pid||':'||p.ppid) FROM proc p WHERE p.host=s.host AND p.utc BETWEEN s.first_utc-600 AND s.last_utc+600) proc_detail
FROM streams s JOIN labels l ON l.host=s.host AND l.domain=s.domain
ORDER BY l.malicious DESC,s.host
"""

cols = [x[0] for x in db.execute(query).description]
print("\t".join(cols))
for row in db.execute(query):
    print("\t".join("" if x is None else str(x) for x in row))

detector = (ROOT / "analysis" / "epilogue-detector.sql").read_text(encoding="utf-8")
predicted = set(db.execute(detector).fetchall())
truth = {(x["host"], x["domain"]) for x in DATA["labels"] if x["malicious"]}
all_labeled = {(x["host"], x["domain"]) for x in DATA["labels"]}
tp = len(predicted & truth)
fp = len(predicted - truth)
fn = len(truth - predicted)
print(f"detector bytes={len(detector.encode())} predictions={len(predicted)} tp={tp} fp={fp} fn={fn}")
print(f"precision={tp/(tp+fp):.3f} recall={tp/(tp+fn):.3f}")
if predicted - all_labeled:
    print("unlabeled predictions:", sorted(predicted - all_labeled))

print("payload samples:")
for want in (1, 0):
    shown = 0
    for label in DATA["labels"]:
        if int(label["malicious"]) != want:
            continue
        rows = db.execute(
            """SELECT nj_sequence(wire_name), nj_payload(wire_name)
               FROM dns d JOIN clocks c USING(sensor)
               JOIN leases l ON l.address=d.address AND d.observed-c.offset BETWEEN l.start AND l.end
               JOIN assets a USING(mac)
               WHERE a.host=? AND nj_domain(wire_name)=?
               GROUP BY 1,2 ORDER BY 1""",
            (label["host"], label["domain"]),
        ).fetchall()
        raw = bytes.fromhex("".join(x[1] for x in rows))
        print(want, label["host"], len(rows), len(raw), raw[:80])
        shown += 1
        if shown == 8:
            break
db.commit()
