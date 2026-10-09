const express=require('express'),multer=require('multer'),bcrypt=require('bcryptjs'),cookieParser=require('cookie-parser'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const PORT=process.env.PORT||3000,DAY=864e5;
const DATA=path.join(__dirname,'data'),UP=path.join(__dirname,'uploads'),DB=path.join(DATA,'db.json');
fs.mkdirSync(DATA,{recursive:true});fs.mkdirSync(UP,{recursive:true});
let db=fs.existsSync(DB)?JSON.parse(fs.readFileSync(DB)):{admin:null,users:[],videos:[]};
const save=()=>fs.writeFileSync(DB,JSON.stringify(db,null,2));
const rid=()=>crypto.randomBytes(6).toString('hex');
if(!db.admin){const l=process.env.ADMIN_LOGIN||'admin',p=process.env.ADMIN_PASSWORD||crypto.randomBytes(5).toString('hex');db.admin={login:l,hash:bcrypt.hashSync(p,10),sid:null};save();console.log(`Админ логині: ${l}  пароль: ${p}`);}
const upload=multer({storage:multer.diskStorage({destination:UP,filename:(q,f,cb)=>cb(null,rid()+path.extname(f.originalname).toLowerCase())}),fileFilter:(q,f,cb)=>cb(null,f.mimetype.startsWith('video/')),limits:{fileSize:2*1024**3}});
const app=express();app.use(express.json(),cookieParser());
const who=q=>{const s=q.cookies.sid;if(!s)return null;if(db.admin.sid===s)return{role:'admin'};const u=db.users.find(u=>u.sid===s);return u?{role:'user',u}:null};
const needUser=(q,r,n)=>{const w=who(q);if(!w)return r.status(401).json({error:'Алдымен кіріңіз'});if(w.role==='user'&&w.u.expires<=Date.now())return r.status(403).json({error:'Доступ мерзімі аяқталды'});q.w=w;n()};
const needAdmin=(q,r,n)=>{const w=who(q);if(!w||w.role!=='admin')return r.status(403).json({error:'Тек админге рұқсат'});n()};
const tries={};
app.post('/api/login',(q,r)=>{
  const t=tries[q.ip]||{n:0,at:0};
  if(t.n>=5&&Date.now()-t.at<9e5)return r.status(429).json({error:'Тым көп әрекет. 15 минуттан кейін қайталаңыз'});
  const{login='',password=''}=q.body;let role=null,rec=null;
  if(login===db.admin.login&&bcrypt.compareSync(password,db.admin.hash)){role='admin';rec=db.admin}
  else{const u=db.users.find(u=>u.login===login);if(u&&bcrypt.compareSync(password,u.hash)){role='user';rec=u}}
  if(!rec){tries[q.ip]={n:t.n+1,at:Date.now()};return r.status(401).json({error:'Логин немесе пароль қате'})}
  delete tries[q.ip];
  if(role==='user'&&rec.expires<=Date.now())return r.status(403).json({error:'Доступ мерзімі аяқталды. Админге жазыңыз'});
  rec.sid=crypto.randomBytes(24).toString('hex');save();
  r.cookie('sid',rec.sid,{httpOnly:true,sameSite:'lax',maxAge:60*DAY});r.json({role});
});
app.post('/api/logout',(q,r)=>{r.clearCookie('sid');r.json({ok:1})});
app.get('/api/me',needUser,(q,r)=>r.json(q.w.role==='admin'?{role:'admin'}:{role:'user',login:q.w.u.login,expires:q.w.u.expires}));
app.get('/api/videos',needUser,(q,r)=>r.json(db.videos.map(({id,title})=>({id,title}))));
app.get('/api/video/:id',needUser,(q,r)=>{const v=db.videos.find(v=>v.id===q.params.id);if(!v)return r.sendStatus(404);r.set('Cache-Control','private, no-store');r.sendFile(path.join(UP,v.file))});
// админ
app.get('/api/admin/users',needAdmin,(q,r)=>r.json(db.users.map(({id,login,expires})=>({id,login,expires}))));
app.post('/api/admin/users',needAdmin,(q,r)=>{
  const{login,password,days}=q.body;
  if(!login||!password||password.length<6)return r.status(400).json({error:'Логин керек, пароль кемінде 6 таңба'});
  if(![14,30,60].includes(+days))return r.status(400).json({error:'Мерзім: 14, 30 немесе 60 күн'});
  if(db.users.some(u=>u.login===login)||login===db.admin.login)return r.status(400).json({error:'Бұл логин бос емес'});
  db.users.push({id:rid(),login,hash:bcrypt.hashSync(password,10),expires:Date.now()+days*DAY,sid:null});save();r.json({ok:1});
});
app.post('/api/admin/users/:id/extend',needAdmin,(q,r)=>{
  const u=db.users.find(u=>u.id===q.params.id);const d=+q.body.days;
  if(!u||![14,30,60].includes(d))return r.sendStatus(400);
  u.expires=Math.max(Date.now(),u.expires)+d*DAY;save();r.json({ok:1});
});
app.post('/api/admin/users/:id/revoke',needAdmin,(q,r)=>{const u=db.users.find(u=>u.id===q.params.id);if(!u)return r.sendStatus(404);u.expires=0;u.sid=null;save();r.json({ok:1})});
app.delete('/api/admin/users/:id',needAdmin,(q,r)=>{db.users=db.users.filter(u=>u.id!==q.params.id);save();r.json({ok:1})});
app.post('/api/admin/videos',needAdmin,upload.single('video'),(q,r)=>{
  if(!q.file)return r.status(400).json({error:'Видео файлын таңдаңыз'});
  db.videos.push({id:rid(),title:(q.body.title||q.file.originalname).slice(0,120),file:q.file.filename});save();r.json({ok:1});
});
app.delete('/api/admin/videos/:id',needAdmin,(q,r)=>{
  const v=db.videos.find(v=>v.id===q.params.id);if(v){fs.rmSync(path.join(UP,v.file),{force:true});db.videos=db.videos.filter(x=>x!==v);save()}r.json({ok:1});
});
// ===== ТЕСТ МОДУЛІ (қазақша + орысша) =====
db.questions=db.questions||[];db.topics=db.topics||Array.from({length:31},(_,i)=>`${i+1}-тақырып`);
db.questions.forEach(x=>{if(!x.kk&&x.text){x.kk={text:x.text,options:x.options,explanation:x.explanation||''};delete x.text;delete x.options;delete x.explanation}});
const lg=l=>l==='ru'?'ru':'kk',attempts={};
const shuf=a=>{a=[...a];for(let i=a.length-1;i>0;i--){const j=crypto.randomInt(i+1);[a[i],a[j]]=[a[j],a[i]]}return a};
const tc=(l,n)=>db.questions.filter(x=>x[l]&&!x.review&&(!n||x.topic===n)).length;
const ttl=(t,l)=>{const p=t.split('|').map(s=>s.trim());return(l==='ru'?p[1]:p[0])||p[0]};
app.get('/api/test/info',needUser,(q,r)=>{const l=lg(q.query.lang);r.json({total:tc(l),
  wrong:(q.w.u?.wrong||[]).filter(id=>db.questions.some(x=>x.id===id&&x[l])).length,
  topics:db.topics.map((t,i)=>({n:i+1,title:ttl(t,l),count:tc(l,i+1),best:q.w.u?.best?.[i+1]??null}))})});
app.post('/api/test/start',needUser,(q,r)=>{
  const{mode,topic}=q.body,l=lg(q.body.lang);let pool=db.questions.filter(x=>x[l]&&!x.review);
  if(mode==='topic')pool=pool.filter(x=>x.topic===+topic);
  if(mode==='mistakes')pool=pool.filter(x=>(q.w.u?.wrong||[]).includes(x.id));
  const list=shuf(pool).slice(0,mode==='topic'?1000:40);
  if(!list.length)return r.status(400).json({error:l==='ru'?(mode==='mistakes'?'Журнал ошибок пуст':'В этом разделе пока нет вопросов'):(mode==='mistakes'?'Қателер дәптері бос':'Бұл бөлімде әлі сұрақ жоқ')});
  const id=rid(),items=list.map(x=>({id:x.id,order:shuf(x[l].options.map((_,k)=>k)),pick:null}));
  attempts[id]={uid:q.w.u?.id,mode,l,topic:mode==='topic'?+topic:0,items};
  const side=(x,o,k)=>x[k]&&{text:x[k].text,options:o.map(j=>x[k].options[j])};
  r.json({id,mode,topic:mode==='topic'?+topic:0,total:list.length,pass:mode==='random'?(list.length>=40?32:Math.ceil(list.length*0.8)):null,
    questions:items.map(it=>{const x=list.find(y=>y.id===it.id);return{kk:side(x,it.order,'kk'),ru:side(x,it.order,'ru'),img:x.img||null}})});
});
app.post('/api/test/:id/answer',needUser,(q,r)=>{
  const a=attempts[q.params.id],{i,choice}=q.body;
  if(!a||a.uid!==q.w.u?.id||!a.items[i]||a.items[i].pick!==null||!(choice in a.items[i].order))return r.sendStatus(400);
  const it=a.items[i],x=db.questions.find(x=>x.id===it.id);if(!x)return r.sendStatus(404);
  it.pick=it.order[choice];const ok=it.pick===x.correct;it.ok=ok;
  if(q.w.u){const w=q.w.u.wrong=q.w.u.wrong||[],has=w.includes(x.id);
    if(!ok&&!has)w.push(x.id);if(ok&&has&&a.mode==='mistakes')w.splice(w.indexOf(x.id),1);save()}
  r.json({ok,correct:it.order.indexOf(x.correct),explanation:{kk:x.kk?.explanation||'',ru:x.ru?.explanation||''}});
});
app.post('/api/test/:id/finish',needUser,(q,r)=>{
  const a=attempts[q.params.id];if(!a||a.uid!==q.w.u?.id)return r.sendStatus(400);
  const total=a.items.length,score=a.items.filter(it=>it.ok).length;
  if(q.w.u&&a.topic){const b=q.w.u.best=q.w.u.best||{},pc=Math.round(score/total*100);b[a.topic]=Math.max(b[a.topic]||0,pc);save()}
  r.json({score,total});
});
function parseCSV(t){
  const L=t.replace(/^\uFEFF/,'').split(/\r?\n/).filter(l=>l.trim()),d=(L[0].match(/;/g)||[]).length>=(L[0].match(/,/g)||[]).length?';':',';
  return L.map(l=>{const c=[];let s='',inq=false;
    for(let i=0;i<l.length;i++){const ch=l[i];
      if(ch==='"'){if(inq&&l[i+1]==='"'){s+='"';i++}else inq=!inq}else if(ch===d&&!inq){c.push(s);s=''}else s+=ch}
    c.push(s);return c.map(x=>x.trim())});
}
function parseQ(txt){
  if(txt.startsWith('['))return JSON.parse(txt).map(o=>({topic:+o.topic,correct:+o.correct-1,kk:o.kk||((o.text||o.q)?{text:o.text||o.q,options:o.options,explanation:o.explanation}:null),ru:o.ru||null}));
  const side=(c,o)=>{const op=c.slice(o+1,o+5).filter(Boolean);return c[o]&&op.length>1?{text:c[o],options:op,explanation:c[o+5]||''}:null};
  return parseCSV(txt).filter((c,i)=>i||!isNaN(+c[0])).map(c=>({topic:+c[0],correct:+c[1]-1,kk:side(c,2),ru:side(c,8)}));
}
app.get('/api/admin/qinfo',needAdmin,(q,r)=>r.json({review:db.questions.filter(x=>x.review).length,kk:tc('kk'),ru:tc('ru'),
  topics:db.topics.map((title,i)=>({n:i+1,title,kk:tc('kk',i+1),ru:tc('ru',i+1)}))}));
app.post('/api/admin/topics',needAdmin,(q,r)=>{
  const t=(q.body.titles||[]).map(s=>String(s).trim()).filter(Boolean).slice(0,31);
  db.topics=Array.from({length:31},(_,i)=>t[i]||`${i+1}-тақырып`);save();r.json({ok:1});
});
app.post('/api/admin/questions/import',needAdmin,(q,r)=>{
  let rows;try{rows=parseQ(String(q.body.text||'').trim())}catch(e){return r.status(400).json({error:'Файл форматы дұрыс емес'})}
  let ok=0,bad=0;
  for(const x of rows){
    const sides=['kk','ru'].filter(l=>x[l]&&x[l].text&&Array.isArray(x[l].options)&&x[l].options.length>1&&x.correct>=0&&x.correct<x[l].options.length);
    if(!(x.topic>=1&&x.topic<=31)||!sides.length||(sides.length===2&&x.kk.options.length!==x.ru.options.length)){bad++;continue}
    const n={id:rid(),topic:x.topic,correct:x.correct};
    sides.forEach(l=>n[l]={text:String(x[l].text),options:x[l].options.map(String),explanation:String(x[l].explanation||'')});
    db.questions.push(n);ok++;
  }
  save();r.json({ok,bad});
});
app.delete('/api/admin/questions',needAdmin,(q,r)=>{
  const t=+q.query.topic;db.questions=t?db.questions.filter(x=>x.topic!==t):[];save();r.json({ok:1});
});

// ===== ТАҚЫРЫП МАЗМҰНЫ =====
db.content=db.content||{};
const imgUp=multer({storage:multer.diskStorage({destination:UP,filename:(q,f,cb)=>cb(null,'img-'+rid()+path.extname(f.originalname).toLowerCase())}),fileFilter:(q,f,cb)=>cb(null,/^image\/(jpeg|png|webp|gif)$/.test(f.mimetype)),limits:{fileSize:10*1024**2}});
const okN=n=>n>=1&&n<=31,C=n=>db.content[n]=db.content[n]||{videoId:null,text:{kk:'',ru:''},images:[]};
app.get('/api/topic/:n',needUser,(q,r)=>{
  const n=+q.params.n,l=lg(q.query.lang),o=l==='kk'?'ru':'kk';if(!okN(n))return r.sendStatus(404);
  const c=db.content[n]||{videoId:null,text:{},images:[]},v=db.videos.find(v=>v.id===c.videoId),k=x=>x==='kk'?'ck':'cr';
  r.json({n,title:ttl(db.topics[n-1],l),videoId:v?v.id:null,text:c.text[l]||c.text[o]||'',
    images:c.images.map(i=>({id:i.id,caption:i[k(l)]||i[k(o)]||''})),count:tc(l,n)});
});
app.get('/api/topic-img/:id',needUser,(q,r)=>{
  const f=path.basename(q.params.id);if(!/^q?img-/.test(f))return r.sendStatus(404);
  r.set('Cache-Control','private, max-age=3600');r.sendFile(path.join(UP,f),e=>{if(e&&!r.headersSent)r.sendStatus(404)});
});
app.get('/api/admin/topic/:n',needAdmin,(q,r)=>okN(+q.params.n)?r.json(db.content[+q.params.n]||{videoId:null,text:{kk:'',ru:''},images:[]}):r.sendStatus(404));
app.post('/api/admin/topic/:n',needAdmin,(q,r)=>{
  const n=+q.params.n;if(!okN(n))return r.sendStatus(404);
  const c=C(n);c.videoId=q.body.videoId||null;c.text={kk:String(q.body.kk||''),ru:String(q.body.ru||'')};save();r.json({ok:1});
});
app.post('/api/admin/topic/:n/images',needAdmin,imgUp.single('image'),(q,r)=>{
  const n=+q.params.n;if(!okN(n)||!q.file)return r.status(400).json({error:'Сурет файлын таңдаңыз (jpg, png, webp)'});
  C(n).images.push({id:q.file.filename,ck:String(q.body.ck||''),cr:String(q.body.cr||'')});save();r.json({ok:1});
});
app.delete('/api/admin/topic/:n/images/:id',needAdmin,(q,r)=>{
  const n=+q.params.n;if(!okN(n))return r.sendStatus(404);
  C(n).images=C(n).images.filter(i=>i.id!==q.params.id);fs.rmSync(path.join(UP,path.basename(q.params.id)),{force:true});save();r.json({ok:1});
});
// ===== WORD/PDF ИМПОРТ ЖӘНЕ СҰРАҚ РЕДАКТОРЫ =====
const mammoth=require('mammoth'),docUp=multer({storage:multer.memoryStorage(),limits:{fileSize:30*1024**2}});
const qimgUp=multer({storage:multer.diskStorage({destination:UP,filename:(q,f,cb)=>cb(null,'qimg-'+rid()+path.extname(f.originalname).toLowerCase())}),fileFilter:(q,f,cb)=>cb(null,/^image\/(jpeg|png|webp|gif)$/.test(f.mimetype)),limits:{fileSize:10*1024**2}});
const dec=s=>s.replace(/&nbsp;/g,' ').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"').replace(/&#39;/g,"'").replace(/&amp;/g,'&');
const OPT=/^\(?([A-Ea-eАБВГДабвгд])\s*[.)]\s*(.+)$/,NUM=/^(?:№\s*)?\d{1,4}\s*[.)]\s*/,MK=/^[*+✓✔]\s*|\s*[*+✓✔]$/g;
const ANS=/^(?:дұрыс\s+жауап|жауап(?:ы)?|правильный\s+ответ|ответ|answer)\s*[:\-–—]?\s*\(?([A-Ea-eАБВГДабвгд1-5])(?![A-Za-zА-Яа-я0-9])/i;
function parseLines(lines,wrap){
  const out=[];let cur=null,pend=[];
  const flush=()=>{if(cur&&cur.q&&cur.opts.length>=2)out.push(cur);cur=null};
  for(const L of lines){
    const t=L.text.replace(/\s+/g,' ').trim();
    if(!t){if(L.imgs.length){if(cur&&cur.opts.length<2)cur.imgs.push(...L.imgs);else pend.push(...L.imgs)}continue}
    const am=t.match(ANS);if(am&&cur&&cur.opts.length>=2){cur.ans=am[1];continue}
    const om=t.match(OPT);
    if(om&&cur&&cur.q){let tx=om[2].trim(),mark=L.bold;if(new RegExp(MK.source).test(tx)){mark=true;tx=tx.replace(MK,'')}
      cur.opts.push({label:om[1],text:tx,mark});cur.imgs.push(...L.imgs);continue}
    if(cur&&!cur.opts.length&&wrap){cur.q+=' '+t;cur.imgs.push(...L.imgs);continue}
    if(cur&&cur.opts.length&&wrap&&!cur.ans&&!NUM.test(t)&&(cur.opts.length<2||!/\?$/.test(t))){cur.opts[cur.opts.length-1].text+=' '+t;continue}
    flush();cur={q:t.replace(NUM,''),opts:[],imgs:[...pend,...L.imgs],ans:null};pend=[];
  }
  flush();return out;
}
app.post('/api/admin/import-doc',needAdmin,docUp.single('file'),async(q,r)=>{
  const topic=+q.body.topic,l=lg(q.body.lang);
  if(!okN(topic)||!q.file)return r.status(400).json({error:'Тақырып пен файлды таңдаңыз'});
  const name=(q.file.originalname||'').toLowerCase(),saved=[];let lines=[],wrap=false;
  try{
    if(name.endsWith('.docx')){
      const res=await mammoth.convertToHtml({buffer:q.file.buffer},{styleMap:['u => u'],convertImage:mammoth.images.imgElement(async im=>{
        const ext={'image/png':'png','image/jpeg':'jpg','image/gif':'gif','image/webp':'webp'}[im.contentType];if(!ext)return{src:''};
        const fn='qimg-'+rid()+'.'+ext;fs.writeFileSync(path.join(UP,fn),await im.read());saved.push(fn);return{src:fn}})});
      lines=res.value.split(/<\/(?:p|li|h[1-6]|tr)>|<br\s*\/?>/i).map(h=>{
        const txt=dec(h.replace(/<[^>]+>/g,'')).trim(),b=[...h.matchAll(/<(strong|b|u)>([\s\S]*?)<\/\1>/gi)].map(m=>m[2].replace(/<[^>]+>/g,'')).join('').trim();
        return{text:txt,bold:txt.length>0&&b.length/txt.length>0.6,imgs:[...h.matchAll(/src="(qimg-[a-z0-9.]+)"/g)].map(m=>m[1])}});
    }else if(name.endsWith('.pdf')){
      const d=await require('pdf-parse/lib/pdf-parse.js')(q.file.buffer);
      lines=d.text.split(/\r?\n/).map(t=>({text:t,bold:false,imgs:[]}));wrap=true;
    }else return r.status(400).json({error:'Тек .docx немесе .pdf файл жүктеңіз'});
  }catch(e){saved.forEach(f=>fs.rmSync(path.join(UP,f),{force:true}));return r.status(400).json({error:'Файлды оқу мүмкін болмады. .doc болса, Word-та .docx ретінде сақтаңыз'})}
  const used=new Set();let added=0,withImg=0,noCorrect=0;
  for(const p of parseLines(lines,wrap)){
    const opts=p.opts.slice(0,5);if(opts.length<2)continue;
    const marks=opts.map((o,i)=>o.mark?i:-1).filter(i=>i>=0);let c=marks.length===1?marks[0]:-1;
    if(c<0&&p.ans){const U=p.ans.toUpperCase();c=opts.findIndex(o=>o.label.toUpperCase()===U);if(c<0){c='ABCDE'.indexOf(U);if(c<0)c='АБВГД'.indexOf(U);if(c<0&&/\d/.test(U))c=+U-1}}
    const ok=c>=0&&c<opts.length,n={id:rid(),topic,correct:ok?c:0,review:true,[l]:{text:p.q,options:opts.map(o=>o.text),explanation:''}};
    if(!ok){n.note='Дұрыс жауап анықталмады. Белгілеп, сақтаңыз';noCorrect++}
    if(p.imgs[0]){n.img=p.imgs[0];used.add(p.imgs[0]);withImg++}
    db.questions.push(n);added++;
  }
  saved.filter(f=>!used.has(f)).forEach(f=>fs.rmSync(path.join(UP,f),{force:true}));save();
  r.json({added,withImg,noCorrect});
});
const qOut=x=>({id:x.id,topic:x.topic,correct:x.correct,kk:x.kk||null,ru:x.ru||null,img:x.img||null,review:!!x.review,note:x.note||''});
app.get('/api/admin/questions',needAdmin,(q,r)=>{
  const t=+q.query.topic||0,s=String(q.query.q||'').toLowerCase().trim(),rv=q.query.review==='1',pg=Math.max(0,+q.query.page||0),PS=10;
  const a=db.questions.filter(x=>(!t||x.topic===t)&&(!rv||x.review)&&(!s||[x.kk?.text,x.ru?.text].some(v=>v&&v.toLowerCase().includes(s))));
  r.json({total:a.length,page:pg,items:a.slice(pg*PS,pg*PS+PS).map(qOut)});
});
function cleanQ(b){
  const topic=+b.topic;if(!okN(topic))return{err:'Тақырыпты таңдаңыз'};const o={topic};
  for(const l of['kk','ru']){const s=b[l];if(!s||!String(s.text||'').trim())continue;
    const op=(s.options||[]).map(v=>String(v).trim());
    if(op.length<2||op.some(v=>!v))return{err:(l==='kk'?'Қазақша':'Орысша')+': жауап нұсқалары толық емес (кемінде 2, бос болмауы керек)'};
    o[l]={text:String(s.text).trim(),options:op,explanation:String(s.explanation||'').trim()}}
  if(!o.kk&&!o.ru)return{err:'Кемінде бір тілде сұрақ мәтіні керек'};
  if(o.kk&&o.ru&&o.kk.options.length!==o.ru.options.length)return{err:'Екі тілдегі жауап саны бірдей болуы керек'};
  const c=+b.correct;if(!(c>=0&&c<(o.kk||o.ru).options.length))return{err:'Дұрыс жауапты белгілеңіз'};
  o.correct=c;return{o};
}
app.post('/api/admin/questions/approve',needAdmin,(q,r)=>{
  const t=+q.body.topic||0;let ok=0,skip=0;
  db.questions.forEach(x=>{if(x.review&&(!t||x.topic===t)){if(x.note)skip++;else{x.review=false;ok++}}});save();r.json({ok,skip});
});
app.post('/api/admin/questions',needAdmin,(q,r)=>{
  const{o,err}=cleanQ(q.body);if(err)return r.status(400).json({error:err});
  const x={id:rid(),...o,review:false};db.questions.push(x);save();r.json({id:x.id});
});
app.put('/api/admin/questions/:id',needAdmin,(q,r)=>{
  const x=db.questions.find(x=>x.id===q.params.id);if(!x)return r.sendStatus(404);
  const{o,err}=cleanQ(q.body);if(err)return r.status(400).json({error:err});
  x.topic=o.topic;x.correct=o.correct;x.review=false;delete x.note;
  ['kk','ru'].forEach(l=>{if(o[l])x[l]=o[l];else delete x[l]});save();r.json({ok:1});
});
app.delete('/api/admin/questions/:id',needAdmin,(q,r)=>{
  const x=db.questions.find(x=>x.id===q.params.id);if(x&&x.img)fs.rmSync(path.join(UP,path.basename(x.img)),{force:true});
  db.questions=db.questions.filter(y=>y!==x);save();r.json({ok:1});
});
const findQ=(q,r,n)=>{q.x=db.questions.find(x=>x.id===q.params.id);q.x?n():r.sendStatus(404)};
app.post('/api/admin/questions/:id/image',needAdmin,findQ,qimgUp.single('image'),(q,r)=>{
  if(!q.file)return r.status(400).json({error:'Сурет файлын таңдаңыз (jpg, png, webp)'});
  if(q.x.img)fs.rmSync(path.join(UP,path.basename(q.x.img)),{force:true});
  q.x.img=q.file.filename;save();r.json({img:q.x.img});
});
app.delete('/api/admin/questions/:id/image',needAdmin,findQ,(q,r)=>{
  if(q.x.img)fs.rmSync(path.join(UP,path.basename(q.x.img)),{force:true});delete q.x.img;save();r.json({ok:1});
});
app.use(express.static(path.join(__dirname,'public')));
app.listen(PORT,()=>console.log(`http://localhost:${PORT}`));
