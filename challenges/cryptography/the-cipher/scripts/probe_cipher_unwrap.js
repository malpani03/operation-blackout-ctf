const crypto = require('crypto');
const fs = require('fs');

const payload = fs.readFileSync('analysis/cipher-envelope.bin');
const checksum = fs.readFileSync('analysis/cipher-transport-checksum.bin');
const archiveKey = 'a7bcdb38d64c8b780d31fab5502551314137f7593df9b7269b29499458be1c6e';
const archives = {
  'id-hex': Buffer.from('7ac51adc827f', 'hex'),
  'id-ascii': Buffer.from('7ac51adc827f'),
  'key-hex': Buffer.from(archiveKey, 'hex'),
  'key-ascii': Buffer.from(archiveKey),
  document: fs.readFileSync('../../forensics/the-evidence/analysis/recovered-document.bin'),
  'document-sha256': crypto.createHash('sha256').update(fs.readFileSync('../../forensics/the-evidence/analysis/recovered-document.bin')).digest(),
  'zip-sha256': crypto.createHash('sha256').update(fs.readFileSync('assets/cipher-acquisition.zip')).digest(),
};
const cals = {
  registered: Buffer.from('388b6eb595bbe45a34137849ecfbebce', 'hex'),
  sorted: Buffer.from('ce5849781f5351b5344e3e6e95fb8bbb', 'hex'),
  'registered-ascii': Buffer.from('388b6eb595bbe45a34137849ecfbebce'),
  'sorted-ascii': Buffer.from('ce5849781f5351b5344e3e6e95fb8bbb'),
};

const keys = {};
for (const [an, archive] of Object.entries(archives)) for (const [cn, cal] of Object.entries(cals)) {
  for (const [on, material] of [['a-c', Buffer.concat([archive, cal])], ['c-a', Buffer.concat([cal, archive])]]) {
    const hash = crypto.createHash('sha256').update(material).digest();
    keys[`${an}/${cn}/${on}/first`] = hash.subarray(0, 16);
    keys[`${an}/${cn}/${on}/last`] = hash.subarray(16);
  }
}

function aes(mode, key, iv, data, padding = false) {
  try {
    const decipher = crypto.createDecipheriv(`aes-128-${mode}`, key, mode === 'ecb' ? null : iv);
    decipher.setAutoPadding(padding);
    return Buffer.concat([decipher.update(data), decipher.final()]);
  } catch { return null; }
}

function repeated(data, width) {
  const seen = new Map();
  const hits = [];
  for (let i = 0; i <= data.length - width; i++) {
    const part = data.subarray(i, i + width).toString('hex');
    if (seen.has(part)) hits.push([seen.get(part), i, part]); else seen.set(part, i);
  }
  return hits;
}

function rank(label, data) {
  if (!data) return;
  const repeats12 = repeated(data, 12);
  const asciiRuns = [...data.toString('latin1').matchAll(/[ -~]{6,}/g)].map(x => [x.index, x[0]]);
  const marker = /journal|action=|archive=|proof=/i.test(data.toString('latin1'));
  const score = repeats12.length * 100 + asciiRuns.reduce((n, x) => n + x[1].length, 0) + (marker ? 10000 : 0);
  if (score > 70) results.push({score, label, bytes: data.length, repeats12: repeats12.slice(0, 5), asciiRuns: asciiRuns.slice(0, 8), head: data.subarray(0, 48).toString('hex')});
}

const results = [];
for (const [keyName, key] of Object.entries(keys)) {
  const ivs = {
    zero: Buffer.alloc(16),
    key,
    'checksum-first': checksum.subarray(0, 16),
    'checksum-last': checksum.subarray(-16),
    'sha-checksum': crypto.createHash('sha256').update(checksum).digest().subarray(0, 16),
    'payload-first': payload.subarray(0, 16),
    'payload-last': payload.subarray(-16),
    'archive-key-first': Buffer.from(archiveKey, 'hex').subarray(0, 16),
    'archive-key-last': Buffer.from(archiveKey, 'hex').subarray(16),
    'header-zero': Buffer.concat([Buffer.from('54525032020007d1', 'hex'), Buffer.alloc(8)]),
    'payload-nonce12-counter0': Buffer.concat([payload.subarray(0, 12), Buffer.alloc(4)]),
    'payload-nonce12-counter1': Buffer.concat([payload.subarray(0, 12), Buffer.from('00000001', 'hex')]),
    'payload-nonce12-counter2': Buffer.concat([payload.subarray(0, 12), Buffer.from('00000002', 'hex')]),
    'payload-nonce8-counter0': Buffer.concat([payload.subarray(0, 8), Buffer.alloc(8)]),
    'payload-nonce8-counter1': Buffer.concat([payload.subarray(0, 8), Buffer.from('0000000000000001', 'hex')]),
  };
  const inputs = {
    all: payload,
    'after16': payload.subarray(16),
    'before16': payload.subarray(0, -16),
    'after1': payload.subarray(1),
    'before1': payload.subarray(0, -1),
    'byte1-after17': payload.subarray(17),
    'after16-before1': payload.subarray(16, -1),
    'after17-before0': payload.subarray(17),
    'before17': payload.subarray(0, -17),
    'after12': payload.subarray(12),
    'before12': payload.subarray(0, -12),
    'after8': payload.subarray(8),
    'before8': payload.subarray(0, -8),
  };
  for (const [ivName, iv] of Object.entries(ivs)) for (const [inputName, input] of Object.entries(inputs)) {
    for (const mode of ['ctr', 'cfb', 'ofb']) rank(`${keyName}/${mode}/${ivName}/${inputName}`, aes(mode, key, iv, input));
    if (input.length % 16 === 0) {
      rank(`${keyName}/cbc/${ivName}/${inputName}`, aes('cbc', key, iv, input));
      rank(`${keyName}/cbc-pad/${ivName}/${inputName}`, aes('cbc', key, iv, input, true));
      rank(`${keyName}/ecb/${inputName}`, aes('ecb', key, null, input));
      rank(`${keyName}/ecb-pad/${inputName}`, aes('ecb', key, null, input, true));
    }
  }
}
results.sort((a, b) => b.score - a.score);
console.log(JSON.stringify({keyCount: Object.keys(keys).length, findings: results.slice(0, 30)}, null, 2));
