const crypto = require('crypto');
const fs = require('fs');
const zlib = require('zlib');

const envelope = fs.readFileSync('analysis/cipher-envelope.bin');
const continuation = fs.readFileSync('analysis/cipher-transport-checksum.bin');
const archiveCredential = Buffer.from(
  'a7bcdb38d64c8b780d31fab5502551314137f7593df9b7269b29499458be1c6e',
  'hex',
);
const registrationCalibration = Buffer.from(
  '388b6eb595bbe45a34137849ecfbebce',
  'hex',
);
const wrapKey = crypto
  .createHash('sha256')
  .update(Buffer.concat([archiveCredential, registrationCalibration]))
  .digest()
  .subarray(0, 16);

const iv = envelope.subarray(0, 16);
const decryptor = crypto.createDecipheriv('aes-128-ctr', wrapKey, iv);
const compressed = Buffer.concat([
  decryptor.update(Buffer.concat([envelope.subarray(16), continuation])),
  decryptor.final(),
]);
const journalBytes = zlib.inflateSync(compressed);
const journal = JSON.parse(journalBytes.toString('utf8'));

fs.writeFileSync('analysis/cipher-journal.zlib', compressed, {flag: 'w'});
fs.writeFileSync('analysis/cipher-journal.json', `${JSON.stringify(journal, null, 2)}\n`, {flag: 'w'});

const duplicates = new Map();
for (const record of journal.records) {
  const entries = duplicates.get(record.nonce) ?? [];
  entries.push(record.queue_seq);
  duplicates.set(record.nonce, entries);
}

console.log(JSON.stringify({
  wrap_key: wrapKey.toString('hex'),
  iv: iv.toString('hex'),
  compressed_bytes: compressed.length,
  journal_bytes: journalBytes.length,
  journal_sha256: crypto.createHash('sha256').update(journalBytes).digest('hex'),
  aad: journal.aad,
  records: journal.records.length,
  repeated_nonces: [...duplicates.entries()].filter(([, sequences]) => sequences.length > 1),
}, null, 2));
