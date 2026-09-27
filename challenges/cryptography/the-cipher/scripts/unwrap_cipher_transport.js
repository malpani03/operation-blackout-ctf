const crypto = require('crypto');
const fs = require('fs');

const payload = fs.readFileSync('analysis/cipher-envelope.bin');
const frame = fs.readFileSync('analysis/cipher-transport-frame.bin');
const documentBytes = fs.readFileSync('../../forensics/the-evidence/analysis/recovered-document.bin');
const document = JSON.parse(documentBytes);
const handover = JSON.parse(fs.readFileSync('../../forensics/the-evidence/analysis/evidence-case-handover.json'));

const registered = Buffer.from('388b6eb595bbe45a34137849ecfbebce3e581f5312c3514e', 'hex');
const sorted = Buffer.from('ce5849781f5351b5344e3e6e95fb8bbbeceb12e4135ac338', 'hex');
const archives = {
  'archive-id-hex': Buffer.from('7ac51adc827f', 'hex'),
  'archive-id-ascii': Buffer.from('7ac51adc827f'),
  'archive-key-hex': Buffer.from(document.archive_key, 'hex'),
  'archive-key-ascii': Buffer.from(document.archive_key),
  'proof-hex': Buffer.from(document.archive_key.slice(0, 24), 'hex'),
  'proof-ascii': Buffer.from(document.archive_key.slice(0, 24)),
  document: documentBytes,
  'task-hex': Buffer.from(document.task, 'hex'),
  'task-ascii': Buffer.from(document.task),
  'receipt-hex': Buffer.from(handover.receipt, 'hex'),
  'receipt-ascii': Buffer.from(handover.receipt),
};
const cals = {
  'registered-raw-first16': registered.subarray(0, 16),
  'sorted-raw-first16': sorted.subarray(0, 16),
  'registered-hex-first16': Buffer.from(registered.toString('hex').slice(0, 16)),
  'sorted-hex-first16': Buffer.from(sorted.toString('hex').slice(0, 16)),
  'registration-file-first16': fs.readFileSync('assets/cipher-acquisition/registrations.log').subarray(0, 16),
  'sensors-file-first16': fs.readFileSync('assets/cipher-acquisition/sensors.yaml').subarray(0, 16),
};

const keys = {};
for (const [archiveName, archive] of Object.entries(archives)) {
  for (const [calName, cal] of Object.entries(cals)) {
    const combinations = {
      'archive-cal': [archive, cal],
      'cal-archive': [cal, archive],
      'archive-pipes-cal': [archive, Buffer.from('||'), cal],
      'cal-pipes-archive': [cal, Buffer.from('||'), archive],
      'archive-colon-cal': [archive, Buffer.from(':'), cal],
    };
    for (const [order, pieces] of Object.entries(combinations)) {
      const digest = crypto.createHash('sha256').update(Buffer.concat(pieces)).digest();
      keys[`${archiveName}/${calName}/${order}/first`] = digest.subarray(0, 16);
      keys[`${archiveName}/${calName}/${order}/last`] = digest.subarray(16);
    }
  }
}

const aads = {
  empty: Buffer.alloc(0),
  header: frame.subarray(0, 8),
  magic: frame.subarray(0, 4),
  'version-flags': frame.subarray(4, 6),
  length: frame.subarray(6, 8),
  checksum: frame.subarray(-20),
  'archive-id-hex': archives['archive-id-hex'],
  'archive-id-ascii': archives['archive-id-ascii'],
};

function decrypt(key, nonce, ciphertext, tag, aad) {
  try {
    const decipher = crypto.createDecipheriv('aes-128-gcm', key, nonce, {authTagLength: tag.length});
    if (aad.length) decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    return null;
  }
}

const layouts = [];
for (const nonceLength of [12, 16]) {
  for (const tagLength of [8, 12, 16]) {
    layouts.push({name: `N${nonceLength}-C-T${tagLength}`, nonce: payload.subarray(0, nonceLength), ciphertext: payload.subarray(nonceLength, -tagLength), tag: payload.subarray(-tagLength)});
    layouts.push({name: `N${nonceLength}-T${tagLength}-C`, nonce: payload.subarray(0, nonceLength), ciphertext: payload.subarray(nonceLength + tagLength), tag: payload.subarray(nonceLength, nonceLength + tagLength)});
    layouts.push({name: `T${tagLength}-N${nonceLength}-C`, nonce: payload.subarray(tagLength, tagLength + nonceLength), ciphertext: payload.subarray(tagLength + nonceLength), tag: payload.subarray(0, tagLength)});
    layouts.push({name: `C-N${nonceLength}-T${tagLength}`, nonce: payload.subarray(-tagLength - nonceLength, -tagLength), ciphertext: payload.subarray(0, -tagLength - nonceLength), tag: payload.subarray(-tagLength)});
  }
}

// The TRP2 trailer is 20 bytes. Some transport formats store a four-byte
// nonce suffix and a 16-byte authentication value there, so test those
// layouts in addition to self-contained envelopes.
const header = frame.subarray(0, 8);
const externalTags = {
  'checksum-first16': frame.subarray(-20, -4),
  'checksum-last16': frame.subarray(-16),
};
const externalNonces = {
  'checksum-first4': frame.subarray(-20, -16),
  'checksum-last4': frame.subarray(-4),
  header,
  'header-checksum-first4': Buffer.concat([header, frame.subarray(-20, -16)]),
  'checksum-first4-header': Buffer.concat([frame.subarray(-20, -16), header]),
  'header-checksum-last4': Buffer.concat([header, frame.subarray(-4)]),
  'checksum-last4-header': Buffer.concat([frame.subarray(-4), header]),
  'magic-checksum-first8': Buffer.concat([header.subarray(0, 4), frame.subarray(-20, -12)]),
  'checksum-first12': frame.subarray(-20, -8),
  'checksum-last12': frame.subarray(-12),
  'checksum-first16': frame.subarray(-20, -4),
  'checksum-last16': frame.subarray(-16),
};
for (const [nonceName, nonce] of Object.entries(externalNonces)) {
  for (const [tagName, tag] of Object.entries(externalTags)) {
    layouts.push({name: `external/${nonceName}/${tagName}/all`, nonce, ciphertext: payload, tag});
    layouts.push({name: `external/${nonceName}/${tagName}/after12`, nonce, ciphertext: payload.subarray(12), tag});
    layouts.push({name: `external/${nonceName}/${tagName}/before12`, nonce, ciphertext: payload.subarray(0, -12), tag});
    layouts.push({name: `external/${nonceName}/${tagName}/after16`, nonce, ciphertext: payload.subarray(16), tag});
    layouts.push({name: `external/${nonceName}/${tagName}/before16`, nonce, ciphertext: payload.subarray(0, -16), tag});
  }
}

const findings = [];
for (const [keyName, key] of Object.entries(keys)) {
  for (const layout of layouts) {
    for (const [aadName, aad] of Object.entries(aads)) {
      const plaintext = decrypt(key, layout.nonce, layout.ciphertext, layout.tag, aad);
      if (plaintext) {
        const output = `analysis/cipher-unwrapped-${findings.length}.bin`;
        fs.writeFileSync(output, plaintext, {flag: 'wx'});
        findings.push({keyName, key: key.toString('hex'), layout: layout.name, aadName, bytes: plaintext.length, output, head: plaintext.subarray(0, 64).toString('hex'), ascii: plaintext.subarray(0, 128).toString('latin1')});
      }
    }
  }
}
console.log(JSON.stringify({keyCount: Object.keys(keys).length, attempts: Object.keys(keys).length * layouts.length * Object.keys(aads).length, findings}, null, 2));
