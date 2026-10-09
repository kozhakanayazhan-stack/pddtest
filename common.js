async function api(url,method='GET',body){
  const o={method,headers:{}};
  if(body instanceof FormData)o.body=body;else if(body){o.headers['Content-Type']='application/json';o.body=JSON.stringify(body)}
  const r=await fetch(url,o);let d={};try{d=await r.json()}catch{}
  if(!r.ok)throw Object.assign(new Error(d.error||'Қате'),{status:r.status});return d;
}
const fmt=t=>new Date(t).toLocaleDateString('kk-KZ',{day:'numeric',month:'long',year:'numeric'});
async function logout(){await api('/api/logout','POST');location.href='/'}

let LANG=localStorage.getItem('lang')==='ru'?'ru':'kk';document.documentElement.lang=LANG;
function langBar(el,onChange){el.innerHTML='';[['kk','ҚАЗ'],['ru','РУС']].forEach(([k,n])=>{const b=document.createElement('button');b.textContent=n;b.className='lg'+(k===LANG?' on':'');
  b.onclick=()=>{if(k===LANG)return;LANG=k;localStorage.setItem('lang',k);document.documentElement.lang=k;langBar(el,onChange);onChange()};el.appendChild(b)})}
