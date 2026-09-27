const crypto=require('crypto'),fs=require('fs');
const payload=fs.readFileSync('analysis/cipher-envelope.bin'),frame=fs.readFileSync('analysis/cipher-transport-frame.bin');
const cal=Buffer.from('388b6eb595bbe45a34137849ecfbebce','hex');
const vals={keyhex:Buffer.from('a7bcdb38d64c8b780d31fab5502551314137f7593df9b7269b29499458be1c6e','hex'),keyascii:Buffer.from('a7bcdb38d64c8b780d31fab5502551314137f7593df9b7269b29499458be1c6e'),idhex:Buffer.from('7ac51adc827f','hex'),idascii:Buffer.from('7ac51adc827f')};
const keys={};for(const [n,v]of Object.entries(vals))for(const [o,m]of[['a-c',Buffer.concat([v,cal])],['c-a',Buffer.concat([cal,v])]]){let h=crypto.createHash('sha256').update(m).digest();keys[`${n}/${o}`]=h.subarray(0,16);}
function check(label,d){let s=d.toString('latin1'),runs=[...s.matchAll(/[ -~]{8,}/g)],printable=runs.reduce((n,x)=>n+x[0].length,0);if(printable>150||/action=|archive=|proof=|journal/i.test(s)){console.log(JSON.stringify({label,head:d.subarray(0,80).toString('hex'),printable,runs:runs.slice(0,10).map(x=>[x.index,x[0]])}));process.exitCode=2;}}
for(const [kn,key]of Object.entries(keys)){
 for(let pos=0;pos<=frame.length-16;pos++){let iv=frame.subarray(pos,pos+16);for(const mode of ['ctr','ofb','cfb']){let x=crypto.createDecipheriv(`aes-128-${mode}`,key,iv),d=Buffer.concat([x.update(payload),x.final()]);check(`${kn}/${mode}/iv16@${pos}/all`,d);}}
 for(let pos=0;pos<=frame.length-12;pos++){let n=frame.subarray(pos,pos+12);for(const ctr of [0,1,2]){let iv=Buffer.concat([n,Buffer.from([0,0,0,ctr])]);let x=crypto.createDecipheriv('aes-128-ctr',key,iv),d=Buffer.concat([x.update(payload),x.final()]);check(`${kn}/ctr/nonce12@${pos}/counter${ctr}/all`,d);}}
}
console.log('done');
