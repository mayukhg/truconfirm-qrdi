const fs = require('fs');
const titles=['Buffer Overflow Vulnerability','Remote Code Execution','Cross-Site Scripting (XSS)','SQL Injection','Privilege Escalation','Information Disclosure','Authentication Bypass','Denial of Service','Directory Traversal','Server-Side Request Forgery'];
const vendors=['Apache','Microsoft','Linux','Cisco','Oracle','VMware','Apple','Google','Mozilla','Adobe'];
const exploits=['Actively Exploited','PoC Exploit','No Public Exploit'];
let out='';
for(let i=0;i<50;i++){
  let cve_id='CVE-'+(2018+Math.floor(Math.random()*7))+'-'+(1000+Math.floor(Math.random()*90000));
  let title=vendors[Math.floor(Math.random()*vendors.length)]+' '+titles[Math.floor(Math.random()*titles.length)];
  let cat=Math.floor(Math.random()*3);
  let tc=cat===0?'false':cat===1?'true':'false';
  let src=cat===2?'unique_ced':'truconfirm';
  let exp=exploits[Math.floor(Math.random()*exploits.length)];
  let assets=Math.floor(Math.random()*100);
  out+=`  { id:'${cve_id}', title:'${title}', tc:${tc}, exploit:'${exp}', assets:${assets}, source:'${src}' },\n`;
}
fs.writeFileSync('cves.txt', out);
