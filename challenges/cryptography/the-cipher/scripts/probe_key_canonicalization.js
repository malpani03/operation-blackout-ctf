const crypto=require('crypto'),fs=require('fs');
const payload=fs.readFileSync('analysis/cipher-envelope.bin');
const keyText='a7bcdb38d64c8b780d31fab5502551314137f7593df9b7269b29499458be1c6e';
const ids=['FC48','7C17','53F5','3F5D','612D','7E55','BD8F','C842','461D','C687','2DD4','18C8','8E05','7506','A10D','15B9','50E5','1698','2F13','2F9E','AC63','EDFF','3DA4','47DD'];
const vals=['38','8b','6e','b5','95','bb','e4','5a','34','13','78','49','ec','fb','eb','ce','3e','58','1f','53','12','c3','51','4e'];
const archives={idhex:Buffer.from('7ac51adc827f','hex'),idascii:Buffer.from('7ac51adc827f'),keyhex:Buffer.from(keyText,'hex'),keyascii:Buffer.from(keyText),document:fs.readFileSync('../../forensics/the-evidence/analysis/recovered-document.bin')};
const cals={};
for(let rotate=0;rotate<24;rotate++){
 const vs=[...vals.slice(rotate),...vals.slice(0,rotate)],is=[...ids.slice(rotate),...ids.slice(0,rotate)];
 const raw=Buffer.from(vs.join(''),'hex');
 cals[`r${rotate}/raw16`]=raw.subarray(0,16);
 cals[`r${rotate}/raw8`]=raw.subarray(0,8);
 cals[`r${rotate}/hex16`]=Buffer.from(vs.join('').slice(0,16));
 cals[`r${rotate}/0x16`]=Buffer.from(vs.map(x=>'0x'+x).join('').slice(0,16));
 cals[`r${rotate}/colon16`]=Buffer.from(vs.join(':').slice(0,16));
 cals[`r${rotate}/idshex16`]=Buffer.from(is.join(''),'hex').subarray(0,16);
 cals[`r${rotate}/idsascii16`]=Buffer.from(is.join('').slice(0,16));
 cals[`r${rotate}/pairs16`]=Buffer.from(is.map((x,i)=>`F-${x}:${vs[i]}`).join(',').slice(0,16));
}
const checksum=fs.readFileSync('analysis/cipher-transport-checksum.bin');
function check(label,d){let s=d.toString('latin1'),runs=[...s.matchAll(/[ -~]{8,}/g)],verified=crypto.createHash('sha1').update(d).digest().equals(checksum);if(verified||/action=|archive=|proof=|journal/i.test(s)||runs.reduce((n,x)=>n+x[0].length,0)>150){console.log(JSON.stringify({label,verified,runs:runs.slice(0,10).map(x=>[x.index,x[0]]),head:d.subarray(0,64).toString('hex')}));process.exitCode=2;}}
for(const[an,a]of Object.entries(archives))for(const[cn,cal]of Object.entries(cals))for(const[on,m]of[['a-c',Buffer.concat([a,cal])],['c-a',Buffer.concat([cal,a])]]){let h=crypto.createHash('sha256').update(m).digest();for(const[part,key]of[['first',h.subarray(0,16)],['last',h.subarray(16)]]){
 for(let ph=0;ph<16;ph++)check(`${an}/${cn}/${on}/${part}/xor/${ph}`,Buffer.from(payload.map((x,i)=>x^key[(i+ph)%16])));
 const ivs={zero:Buffer.alloc(16),key,last:h.subarray(16),cal:Buffer.concat([cal,Buffer.alloc(Math.max(0,16-cal.length))]).subarray(0,16),nonce0:Buffer.concat([payload.subarray(0,12),Buffer.alloc(4)]),nonce1:Buffer.concat([payload.subarray(0,12),Buffer.from('00000001','hex')])};
 for(const[ivn,iv]of Object.entries(ivs))for(const mode of ['ctr','cfb8'])for(const[inn,input]of[['all',payload],['after12',payload.subarray(12)],['after16',payload.subarray(16)]]){let d=crypto.createDecipheriv(`aes-128-${mode}`,key,iv);check(`${an}/${cn}/${on}/${part}/${mode}/${ivn}/${inn}`,Buffer.concat([d.update(input),d.final()]));}
}}
console.log('done');
