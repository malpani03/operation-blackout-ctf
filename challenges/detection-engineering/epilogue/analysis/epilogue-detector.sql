WITH
framed AS (
  SELECT d.address,
         d.observed - c.offset AS utc,
         nj_sequence(d.wire_name) AS seq,
         nj_payload(d.wire_name) AS payload,
         nj_claimed_crc(d.wire_name) AS claimed_crc,
         nj_crc16(d.wire_name) AS actual_crc,
         nj_stream(d.wire_name) AS stream,
         nj_domain(d.wire_name) AS domain
  FROM dns AS d
  JOIN clocks AS c ON c.sensor = d.sensor
  WHERE d.qtype = 'TXT'
),
attributed AS (
  SELECT a.host, f.domain, f.stream, f.seq, f.payload,
         f.claimed_crc, f.actual_crc, f.utc
  FROM framed AS f
  JOIN leases AS l
    ON l.address = f.address
   AND f.utc BETWEEN l.start AND l.end
  JOIN assets AS a ON a.mac = l.mac
  WHERE f.stream IS NOT NULL
),
chunks AS (
  SELECT host, domain, stream, seq, payload,
         MIN(utc) AS first_seen,
         MIN(actual_crc = claimed_crc) AS crc_ok
  FROM attributed
  GROUP BY host, domain, stream, seq, payload
),
complete_streams AS (
  SELECT host, domain, stream,
         MIN(first_seen) AS first_seen
  FROM chunks
  GROUP BY host, domain, stream
  HAVING MIN(seq) = 0
     AND COUNT(*) >= 10
     AND MAX(seq) + 1 = COUNT(*)
     AND COUNT(DISTINCT seq) = COUNT(*)
     AND MIN(crc_ok) = 1
),
module_events AS (
  SELECT m.host, m.pid, m.module_hash,
         m.local_time - c.offset AS utc
  FROM modules AS m
  JOIN clocks AS c ON c.sensor = m.sensor
)
SELECT DISTINCT s.host AS host, s.domain AS domain
FROM complete_streams AS s
JOIN module_events AS m
  ON m.host = s.host
 AND m.utc BETWEEN s.first_seen - 60 AND s.first_seen
JOIN processes AS p
  ON p.host = m.host
 AND p.pid = m.pid
JOIN clocks AS pc ON pc.sensor = p.sensor
WHERE p.local_time - pc.offset BETWEEN s.first_seen - 300 AND m.utc
  AND EXISTS (
    SELECT 1
    FROM processes AS parent
    WHERE parent.host = p.host
      AND parent.pid = p.ppid
  )
  AND NOT EXISTS (
    SELECT 1
    FROM files AS f
    JOIN certificates AS cert ON cert.subject = f.signer
    WHERE f.digest = m.module_hash
      AND m.utc BETWEEN cert.valid_from AND cert.valid_to
      AND (cert.revoked_at IS NULL OR cert.revoked_at > m.utc)
  )
  AND NOT EXISTS (
    SELECT 1
    FROM deployments AS d
    WHERE d.host = m.host
      AND d.module_hash = m.module_hash
      AND m.utc BETWEEN d.start AND d.end
      AND (
        SELECT ch.state
        FROM changes AS ch
        WHERE ch.deployment_id = d.id
        ORDER BY ch.sequence DESC
        LIMIT 1
      ) = 'approved'
  );
