const crypto = require('crypto');
const fs = require('fs');
const https = require('https');

const masterKey = Buffer.from(process.env.HX_MASTER_KEY_B64, 'base64');
const encrypted = Buffer.from(process.env.HX_COOKIE_ENC_B64, 'base64');

if (encrypted.subarray(0, 3).toString('ascii') !== 'v10') {
  throw new Error('Unsupported Chromium cookie encryption format');
}

const nonce = encrypted.subarray(3, 15);
const ciphertext = encrypted.subarray(15, encrypted.length - 16);
const tag = encrypted.subarray(encrypted.length - 16);
const decipher = crypto.createDecipheriv('aes-256-gcm', masterKey, nonce);
decipher.setAuthTag(tag);
let plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
const hostDigest = crypto.createHash('sha256').update('ctf.roshancodes.com').digest();
const strippedHostDigest = plaintext.subarray(0, 32).equals(hostDigest);
if (strippedHostDigest) plaintext = plaintext.subarray(32);
const cookie = plaintext.toString('utf8');
console.log(JSON.stringify({
  strippedHostDigest,
  plaintextLength: plaintext.length,
  cookieLength: cookie.length,
  visibleAscii: /^[\x21-\x7e]+$/.test(cookie),
  utf8RoundTrip: Buffer.from(cookie, 'utf8').equals(plaintext),
  jwtLike: cookie.split('.').length === 3,
}));

const output = fs.createWriteStream('assets/bundle.zip', { flags: 'wx' });
const request = https.get({
  hostname: 'ctf.roshancodes.com',
  path: '/evidence/bundle.zip',
  headers: { Cookie: `hx_player=${cookie}` },
}, (response) => {
  if (response.statusCode !== 200) {
    output.close();
    fs.unlinkSync('assets/bundle.zip');
    throw new Error(`Download failed with HTTP ${response.statusCode}`);
  }
  response.pipe(output);
  output.on('finish', () => output.close(() => console.log('bundle.zip downloaded')));
});
request.on('error', (error) => {
  output.close();
  if (fs.existsSync('assets/bundle.zip')) fs.unlinkSync('assets/bundle.zip');
  throw error;
});
