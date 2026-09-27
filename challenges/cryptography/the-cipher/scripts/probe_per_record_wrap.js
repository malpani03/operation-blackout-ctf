const c=require('crypto'),f=require('fs'),p=f.readFileSync('analysis/cipher-envelope.bin');
const cal=Buffer.from('388b6eb595bbe45a34137849ecfbebce','hex');
const vals={id:Buffer.from('7ac51adc827f','hex'),key:Buffer.from('a7bcdb38d64c8b780d31fab5502551314137f7593df9b7269b29499458be1c6e','hex')};
function chk(n,o){let s=o.toString('latin1'),runs=[...s.matchAll(/[ -~]{8,}/g)],seen=new Set,dup=0;for(let i=0;i<o.length-11;i++){let x=o.subarray(i,i+12).toString('hex');if(seen.has(x))dup++;seen.add(x)}if(dup||runs.reduce((a,x)=>a+x[0].length,0)>100||/action=|archive=|proof=|journal/i.test(s))console.log(JSON.stringify({n,dup,runs:runs.slice(0,20).map(x=>[x.index,x[0]]),head:o.subarray(0,80).toString('hex')}));}
for(const[n,v]of Object.entries(vals))for(const[ord,m]of[['a-c',Buffer.concat([v,cal])],['c-a',Buffer.concat([cal,v])]]){
 let h=c.createHash('sha256').update(m).digest();
 for(const[part,k]of[['first',h.subarray(0,16)],['last',h.subarray(16)]]){
  for(const[ivn,iv]of[['zero',Buffer.alloc(16)],['cal',cal],['last',h.subarray(16)]])for(const mode of ['ctr','ofb','cfb8']){let outs=[];for(let i=0;i<23;i++){let d=c.createDecipheriv('aes-128-'+mode,k,iv),r=p.subarray(i*87,(i+1)*87);outs.push(Buffer.concat([d.update(r),d.final()]));}chk(n+'/'+ord+'/'+part+'/'+mode+'/'+ivn,Buffer.concat(outs));}
  let o=Buffer.alloc(p.length);for(let i=0;i<23;i++)for(let j=0;j<87;j++)o[i*87+j]=p[i*87+j]^k[j%16];chk(n+'/'+ord+'/'+part+'/xor-reset',o);
 }
}
