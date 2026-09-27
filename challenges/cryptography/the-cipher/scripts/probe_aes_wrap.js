const crypto = require('crypto');
const fs = require('fs');
const payload = fs.readFileSync('analysis/cipher-envelope.bin');
const archiveKey = 'a7bcdb38d64c8b780d31fab5502551314137f7593df9b7269b29499458be1c6e';
const archives = {
  'id-hex': Buffer.from('7ac51adc827f', 'hex'),
  'id-ascii': Buffer.from('7ac51adc827f'),
  'key-hex': Buffer.from(archiveKey, 'hex'),
  'key-ascii': Buffer.from(archiveKey),
};
const cals = {
  registered: Buffer.from('388b6eb595bbe45a34137849ecfbebce', 'hex'),
  sorted: Buffer.from('ce5849781f5351b5344e3e6e95fb8bbb', 'hex'),
  'registered-ascii': Buffer.from('388b6eb595bbe45a34137849ecfbebce'),
  'sorted-ascii': Buffer.from('ce5849781f5351b5344e3e6e95fb8bbb'),
};
const keys = {};
for (const [an, a] of Object.entries(archives)) for (const [cn, c] of Object.entries(cals)) for (const [on, m] of [['a-c',Buffer.concat([a,c])],['c-a',Buffer.concat([c,a])]]) {
  const h=crypto.createHash('sha256').update(m).digest(); keys[`${an}/${cn}/${on}/first`]=h.subarray(0,16); keys[`${an}/${cn}/${on}/last`]=h.subarray(16);
}
const inputs={'after1':payload.subarray(1),'before1':payload.subarray(0,-1)};
const configs=[['aes128-wrap',Buffer.alloc(8,0xa6)],['aes128-wrap-pad',Buffer.from('a65959a6','hex')]];
const findings=[];
for(const [kn,key] of Object.entries(keys)) for(const [inputName,input] of Object.entries(inputs)) for(const [alg,iv] of configs){
  try { const d=crypto.createDecipheriv(alg,key,iv); const p=Buffer.concat([d.update(input),d.final()]); findings.push({kn,key:key.toString('hex'),inputName,alg,bytes:p.length,head:p.subarray(0,80).toString('hex'),ascii:p.subarray(0,200).toString('latin1')}); } catch {}
}
for(const [kn,key] of Object.entries(keys)) for(let start=0;start<=40;start++) for(let trim=0;trim<=40;trim++) {
  const input=payload.subarray(start,payload.length-trim);
  if(input.length<1900 || input.length%8) continue;
  for(const [alg,iv] of configs) try {
    const d=crypto.createDecipheriv(alg,key,iv), p=Buffer.concat([d.update(input),d.final()]);
    findings.push({kn,key:key.toString('hex'),inputName:`slice-${start}-${trim}`,alg,bytes:p.length,head:p.subarray(0,80).toString('hex'),ascii:p.subarray(0,200).toString('latin1')});
  } catch {}
}
console.log(JSON.stringify({findings},null,2));
