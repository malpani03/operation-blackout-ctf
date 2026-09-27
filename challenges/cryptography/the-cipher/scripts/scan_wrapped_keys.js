const crypto=require('crypto'),fs=require('fs'),payload=fs.readFileSync('analysis/cipher-envelope.bin');
const keyText='a7bcdb38d64c8b780d31fab5502551314137f7593df9b7269b29499458be1c6e',registered=Buffer.from('388b6eb595bbe45a34137849ecfbebce','hex'),sorted=Buffer.from('ce5849781f5351b5344e3e6e95fb8bbb','hex');
const archives={idhex:Buffer.from('7ac51adc827f','hex'),idascii:Buffer.from('7ac51adc827f'),keyhex:Buffer.from(keyText,'hex'),keyascii:Buffer.from(keyText),document:fs.readFileSync('../../forensics/the-evidence/analysis/recovered-document.bin')};
const cals={registered,sorted,'registered-hex16':Buffer.from(registered.toString('hex').slice(0,16)),'sorted-hex16':Buffer.from(sorted.toString('hex').slice(0,16))};
const keys={};for(const[an,a]of Object.entries(archives))for(const[cn,c]of Object.entries(cals))for(const[on,m]of[['a-c',Buffer.concat([a,c])],['c-a',Buffer.concat([c,a])]]){let h=crypto.createHash('sha256').update(m).digest();keys[`${an}/${cn}/${on}/first`]=h.subarray(0,16);keys[`${an}/${cn}/${on}/last`]=h.subarray(16);}
const configs=[['aes128-wrap',Buffer.alloc(8,0xa6)],['aes128-wrap-pad',Buffer.from('a65959a6','hex')]],findings=[];
const likelyKeys=Object.entries(keys).filter(([name])=>/(keyhex|idhex)\/registered\/a-c\/first$/.test(name));
for(const[kn,key]of likelyKeys)for(const[alg,iv]of configs)for(const length of [16,24,32,40])for(let at=0;at<=payload.length-length;at++)try{let d=crypto.createDecipheriv(alg,key,iv),p=Buffer.concat([d.update(payload.subarray(at,at+length)),d.final()]);findings.push({kn,key:key.toString('hex'),alg,at,length,unwrapped:p.length,plaintext:p.toString('hex')});}catch{}
console.log(JSON.stringify({keys:Object.keys(keys).length,findings},null,2));
