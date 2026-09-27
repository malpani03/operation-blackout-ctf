const crypto = require('crypto');
const fs = require('fs');

const payload = fs.readFileSync('analysis/cipher-envelope.bin');
const calibration = Buffer.from('388b6eb595bbe45a34137849ecfbebce', 'hex');
const values = {
  'archive-id-hex': Buffer.from('7ac51adc827f', 'hex'),
  'archive-id-ascii': Buffer.from('7ac51adc827f'),
  'proof-hex': Buffer.from('a7bcdb38d64c8b780d31fab5', 'hex'),
  'proof-ascii': Buffer.from('a7bcdb38d64c8b780d31fab5'),
  'archive-key-hex': Buffer.from('a7bcdb38d64c8b780d31fab5502551314137f7593df9b7269b29499458be1c6e', 'hex'),
  'archive-key-ascii': Buffer.from('a7bcdb38d64c8b780d31fab5502551314137f7593df9b7269b29499458be1c6e'),
};

const keys = {};
for (const [name, value] of Object.entries(values)) {
  for (const [order, material] of [
    ['archive-cal', Buffer.concat([value, calibration])],
    ['cal-archive', Buffer.concat([calibration, value])],
  ]) {
    const digest = crypto.createHash('sha256').update(material).digest();
    keys[`${name}/${order}/first`] = digest.subarray(0, 16);
    keys[`${name}/${order}/last`] = digest.subarray(16);
  }
}

const layouts = {
  'N-C-T': [0, 12, 60],
  'N-T-C': [0, 28, 12],
  'T-N-C': [16, 28, 0],
  'T-C-N': [64, 16, 0],
  'C-N-T': [48, 0, 60],
  'C-T-N': [64, 0, 48],
};

function decrypt(key, nonce, ciphertext, tag, aad) {
  try {
    const decipher = crypto.createDecipheriv('aes-128-gcm', key, nonce, {authTagLength: 16});
    if (aad.length) decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    return null;
  }
}

const aadValues = {
  empty: Buffer.alloc(0),
  'archive-id-hex': values['archive-id-hex'],
  'archive-id-ascii': values['archive-id-ascii'],
  'proof-hex': values['proof-hex'],
  'proof-ascii': values['proof-ascii'],
};
const findings = [];
for (const [keyName, key] of Object.entries(keys)) {
  for (let start = 0; start <= payload.length - 76; start++) {
    const window = payload.subarray(start, start + 76);
    for (const [layoutName, [nonceAt, cipherAt, tagAt]] of Object.entries(layouts)) {
      const nonce = window.subarray(nonceAt, nonceAt + 12);
      const ciphertext = window.subarray(cipherAt, cipherAt + 48);
      const tag = window.subarray(tagAt, tagAt + 16);
      for (const [aadName, aad] of Object.entries(aadValues)) {
        const plaintext = decrypt(key, nonce, ciphertext, tag, aad);
        if (plaintext) findings.push({keyName, key: key.toString('hex'), start, layoutName, aadName, nonce: nonce.toString('hex'), tag: tag.toString('hex'), plaintext: plaintext.toString('latin1')});
      }
    }
  }
}
console.log(JSON.stringify({keyCount: Object.keys(keys).length, findings}, null, 2));
