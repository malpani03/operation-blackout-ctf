'use strict';

const fs = require('fs');
const crypto = require('crypto');

const corePath = process.argv[2] || 'assets/implant-process.core';
const deviceKeyHex = process.argv[3] || '64c5d828bac56fe9037c4a188d21652c0df5221c6118320ee36541d32c01dcf7';
const filterIndex = process.argv[4] === undefined ? null : Number(process.argv[4]);
const deviceKey = Buffer.from(deviceKeyHex, 'hex');
const core = fs.readFileSync(corePath);
const MASK64 = (1n << 64n) - 1n;

function rol64(value, bits) {
  return ((value << BigInt(bits)) | (value >> BigInt(64 - bits))) & MASK64;
}

function ror64(value, bits) {
  return ((value >> BigInt(bits)) | (value << BigInt(64 - bits))) & MASK64;
}

function hex64(value) {
  return `0x${value.toString(16).padStart(16, '0')}`;
}

function readSegments() {
  if (!core.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))) {
    throw new Error('not ELF');
  }
  const phoff = Number(core.readBigUInt64LE(0x20));
  const phentsize = core.readUInt16LE(0x36);
  const phnum = core.readUInt16LE(0x38);
  const segments = [];
  for (let index = 0; index < phnum; index += 1) {
    const offset = phoff + index * phentsize;
    if (core.readUInt32LE(offset) !== 1) continue;
    const fileOffset = Number(core.readBigUInt64LE(offset + 8));
    const vaddr = core.readBigUInt64LE(offset + 16);
    const fileSize = Number(core.readBigUInt64LE(offset + 32));
    segments.push({ fileOffset, vaddr, data: core.subarray(fileOffset, fileOffset + fileSize) });
  }
  return segments;
}

const segments = readSegments();

function readVirtual(address, length) {
  const segment = segments.find((item) => address >= item.vaddr && address + BigInt(length) <= item.vaddr + BigInt(item.data.length));
  if (!segment) throw new Error(`unmapped address ${hex64(address)} length=${length}`);
  const offset = Number(address - segment.vaddr);
  return segment.data.subarray(offset, offset + length);
}

function parseHeader(buffer, segment, relative) {
  const encodedHead = buffer.readBigUInt64LE(0x10);
  const headCookie = buffer.readBigUInt64LE(0x18);
  return {
    address: segment.vaddr + BigInt(relative),
    version: buffer.readUInt32LE(4),
    owner: buffer.readUInt32LE(8),
    generation: buffer.readUInt32LE(0x0c),
    encodedHead,
    headCookie,
    head: rol64(encodedHead, 23) ^ headCookie,
    byteCount: Number(buffer.readBigUInt64LE(0x20)),
    tokenA: Buffer.from(buffer.subarray(0x28, 0x38)),
    tokenB: Buffer.from(buffer.subarray(0x38, 0x48)),
    nonce: Buffer.from(buffer.subarray(0x48, 0x54)),
    nodeCount: buffer.readUInt32LE(0x54),
    raw: Buffer.from(buffer),
  };
}

function findHeaders() {
  const headers = [];
  for (const segment of segments) {
    let relative = -1;
    while ((relative = segment.data.indexOf('RCTX', relative + 1, 'ascii')) !== -1) {
      if (relative + 0x5c > segment.data.length) continue;
      const buffer = segment.data.subarray(relative, relative + 0x5c);
      if (buffer.readUInt32LE(4) === 4) headers.push(parseHeader(buffer, segment, relative));
    }
  }
  return headers;
}

function recoverContext(header, saltMode) {
  const chunks = [];
  let address = header.head;
  for (let index = 0; index < header.nodeCount; index += 1) {
    const node = readVirtual(address, 0x70);
    const guard = rol64(address, 9) ^ header.encodedHead;
    const owner = node.readUInt32LE(0x10);
    const generation = node.readUInt32LE(0x14);
    const ordinal = node.readUInt32LE(0x18);
    const length = node.readUInt32LE(0x1c);
    if (node.readBigUInt64LE(8) !== guard || owner !== header.owner || generation !== header.generation || ordinal !== index || length > 0x50) {
      throw new Error(`invalid node ${index} at ${hex64(address)}`);
    }
    const seed = Buffer.alloc(20);
    const packedIdentity = node.readBigUInt64LE(0x10);
    const saltCandidates = {
      address,
      encoded_head: header.encodedHead,
      head_cookie: header.headCookie,
      head: header.head,
      address_xor_encoded: address ^ header.encodedHead,
      address_xor_cookie: address ^ header.headCookie,
      guard,
      identity: packedIdentity,
      header_address: header.address,
      zero: 0n,
      token_a0: header.tokenA.readBigUInt64LE(0),
      token_a1: header.tokenA.readBigUInt64LE(8),
      token_b0: header.tokenB.readBigUInt64LE(0),
      token_b1: header.tokenB.readBigUInt64LE(8),
    };
    seed.writeBigUInt64LE(saltCandidates[saltMode], 0);
    seed.writeBigUInt64LE(node.readBigUInt64LE(0x10), 8);
    seed.writeUInt32LE(ordinal, 16);
    const pad = crypto.createHash('sha256').update(seed).digest();
    const clear = Buffer.alloc(length);
    for (let offset = 0; offset < length; offset += 1) {
      clear[offset] = node[0x20 + offset] ^ pad[offset & 31];
    }
    chunks.push(clear);
    const encodedNext = node.readBigUInt64LE(0);
    address = ror64(encodedNext, 17) ^ header.encodedHead ^ address;
  }
  const ciphertext = Buffer.concat(chunks);
  if (ciphertext.length !== header.byteCount) {
    throw new Error(`byte count mismatch: got ${ciphertext.length}, expected ${header.byteCount}`);
  }
  const derivation = Buffer.alloc(0x32);
  derivation.write('HX-resume\0', 0, 'ascii');
  derivation.writeUInt32LE(header.owner, 0x0a);
  derivation.writeUInt32LE(header.generation, 0x0e);
  for (let index = 0; index < 16; index += 1) {
    derivation[0x12 + index] = header.tokenB[index] ^ 0xa7;
    derivation[0x22 + index] = header.tokenB[index] ^ 0xa7 ^ header.tokenA[index];
  }
  const key = crypto.createHmac('sha256', deviceKey).update(derivation).digest();
  const body = ciphertext.subarray(0, -16);
  const tag = ciphertext.subarray(-16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, header.nonce);
  decipher.setAAD(header.raw.subarray(8, 0x10));
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(body), decipher.final()]);
  return { ciphertext, plaintext, key, finalAddress: address };
}

function printable(buffer) {
  return [...buffer].map((byte) => byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : '.').join('');
}

const crcTable = Array.from({ length: 256 }, (_, index) => {
  let value = index;
  for (let bit = 0; bit < 8; bit += 1) value = (value & 1) ? (0xedb88320 ^ (value >>> 1)) : (value >>> 1);
  return value >>> 0;
});

function scanRecordCrcs(buffer, minimumPrefix = 4, maximumPrefix = 200) {
  const matches = [];
  for (let start = 0; start + minimumPrefix + 4 <= buffer.length; start += 1) {
    let state = 0xffffffff;
    const limit = Math.min(maximumPrefix, buffer.length - start - 4);
    for (let prefixLength = 1; prefixLength <= limit; prefixLength += 1) {
      state = crcTable[(state ^ buffer[start + prefixLength - 1]) & 0xff] ^ (state >>> 8);
      if (prefixLength < minimumPrefix) continue;
      const calculated = (state ^ 0xffffffff) >>> 0;
      const stored = buffer.readUInt32LE(start + prefixLength);
      if (calculated === stored) matches.push({ start, prefixLength, totalLength: prefixLength + 4 });
    }
  }
  return matches;
}

const headers = findHeaders();
const saltModes = ['address', 'encoded_head', 'head_cookie', 'head', 'address_xor_encoded', 'address_xor_cookie', 'guard', 'identity', 'header_address', 'zero', 'token_a0', 'token_a1', 'token_b0', 'token_b1'];
console.log(`headers=${headers.length}`);
let authenticated = 0;
for (let index = 0; index < headers.length; index += 1) {
  if (filterIndex !== null && index !== filterIndex) continue;
  const header = headers[index];
  try {
    let recovered;
    let saltMode;
    let lastError;
    for (saltMode of saltModes) {
      try {
        recovered = recoverContext(header, saltMode);
        break;
      } catch (error) {
        lastError = error;
      }
    }
    if (!recovered) throw lastError;
    authenticated += 1;
    console.log(`\n[${String(index).padStart(3, '0')}] AUTH owner=${header.owner} generation=${header.generation} nodes=${header.nodeCount} bytes=${header.byteCount} head=${hex64(header.head)} end=${hex64(recovered.finalAddress)} salt=${saltMode}`);
    console.log(`key=${recovered.key.toString('hex')}`);
    console.log(`plain[0:256]=${recovered.plaintext.subarray(0, 256).toString('hex')}`);
    console.log(`ascii[0:256]=${printable(recovered.plaintext.subarray(0, 256))}`);
    if (filterIndex !== null) {
      console.log(`plain_full=${recovered.plaintext.toString('hex')}`);
      console.log(`crc_matches=${JSON.stringify(scanRecordCrcs(recovered.plaintext))}`);
    }
  } catch (error) {
    if (!String(error.message).includes('Unsupported state or unable to authenticate data')) {
      console.log(`[${String(index).padStart(3, '0')}] FAIL owner=${header.owner} generation=${header.generation}: ${error.message}`);
    }
  }
}
console.log(`\nauthenticated=${authenticated}/${headers.length}`);
