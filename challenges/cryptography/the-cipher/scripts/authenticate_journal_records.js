const crypto = require('crypto');
const fs = require('fs');

const payload = fs.readFileSync('analysis/cipher-envelope.bin');
const documentBytes = fs.readFileSync('../../forensics/the-evidence/analysis/recovered-document.bin');
const document = JSON.parse(documentBytes);
const handover = JSON.parse(fs.readFileSync('../../forensics/the-evidence/analysis/evidence-case-handover.json'));
const registered = Buffer.from('388b6eb595bbe45a34137849ecfbebce3e581f5312c3514e', 'hex');
const sorted = Buffer.from('ce5849781f5351b5344e3e6e95fb8bbbeceb12e4135ac338', 'hex');

const archives = {
  'id-hex': Buffer.from('7ac51adc827f', 'hex'),
  'id-ascii': Buffer.from('7ac51adc827f'),
  'key-hex': Buffer.from(document.archive_key, 'hex'),
  'key-ascii': Buffer.from(document.archive_key),
  'proof-hex': Buffer.from(document.archive_key.slice(0, 24), 'hex'),
  'proof-ascii': Buffer.from(document.archive_key.slice(0, 24)),
  document: documentBytes,
  'receipt-hex': Buffer.from(handover.receipt, 'hex'),
};
const cals = {
  registered: registered.subarray(0, 16),
  sorted: sorted.subarray(0, 16),
  'registered-ascii': Buffer.from(registered.toString('hex').slice(0, 16)),
  'sorted-ascii': Buffer.from(sorted.toString('hex').slice(0, 16)),
};
const keys = {};
for (const [an,a] of Object.entries(archives)) for (const [cn,c] of Object.entries(cals)) {
  for (const [on,m] of [['a-c',Buffer.concat([a,c])],['c-a',Buffer.concat([c,a])],['a-pipes-c',Buffer.concat([a,Buffer.from('||'),c])]]) {
    const h=crypto.createHash('sha256').update(m).digest();
    keys[`${an}/${cn}/${on}/first`]=h.subarray(0,16);
    keys[`${an}/${cn}/${on}/last`]=h.subarray(16);
  }
}

function permutations(items) {
  if (items.length === 1) return [items];
  return items.flatMap((x,i) => permutations(items.filter((_,j)=>j!==i)).map(rest=>[x,...rest]));
}
const widths={M:11,N:12,C:48,T:16};
const layouts=permutations(['M','N','C','T']).map(order=>{
  let at=0, fields={}; for(const name of order){fields[name]=[at,at+widths[name]];at+=widths[name];}
  return {name:order.join('-'),fields};
});
function dec(key,n,c,t,aad){try{const d=crypto.createDecipheriv('aes-128-gcm',key,n,{authTagLength:16});if(aad.length)d.setAAD(aad);d.setAuthTag(t);return Buffer.concat([d.update(c),d.final()]);}catch{return null;}}
const findings=[];
for(const [kn,key] of Object.entries(keys)) for(let i=0;i<23;i++){
  const record=payload.subarray(i*87,(i+1)*87);
  for(const layout of layouts){const f=layout.fields,n=record.subarray(...f.N),c=record.subarray(...f.C),t=record.subarray(...f.T),m=record.subarray(...f.M);
    const aads={metadata:m,empty:Buffer.alloc(0),'metadata-index':Buffer.concat([m,Buffer.from([i])]),'index-metadata':Buffer.concat([Buffer.from([i]),m])};
    for(const [aadName,aad] of Object.entries(aads)){const p=dec(key,n,c,t,aad);if(p)findings.push({kn,key:key.toString('hex'),record:i,layout:layout.name,aadName,metadata:m.toString('hex'),nonce:n.toString('hex'),ciphertext:c.toString('hex'),tag:t.toString('hex'),plaintext:p.toString('latin1')});}
  }
}
console.log(JSON.stringify({keys:Object.keys(keys).length,layouts:layouts.length,findings},null,2));
