const crypto = require('crypto');
const fs = require('fs');

const packagePath = process.argv[2] || 'assets/cipher-package.json';
const outputPath = process.argv[3] || 'assets/cipher-acquisition.zip';

const envelope = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
if (envelope.format !== 'zip') {
  throw new Error(`Unexpected package format: ${envelope.format}`);
}

const acquisition = Buffer.from(envelope.acquisition_base64, 'base64');
const digest = crypto.createHash('sha256').update(acquisition).digest('hex');
if (digest !== envelope.sha256) {
  throw new Error(`SHA-256 mismatch: expected ${envelope.sha256}, got ${digest}`);
}

fs.writeFileSync(outputPath, acquisition, { flag: 'wx' });
console.log(JSON.stringify({ outputPath, bytes: acquisition.length, sha256: digest }));
