/* ===== الحسابات والأمان (نسخة أولية) =====
   AUTH.mode "local": الحسابات تُحفظ في هذا المتصفح فقط (للتجربة). لا تُغني عن حماية الخادم.
   للإنتاج: استبدل doSignup وdoLogin بنداءات إلى خادمك (AUTH.endpoint) وأبقِ طبقات الواجهة كما هي. */
const AUTH={mode:"local",endpoint:"",allowedDomains:[],adminEmails:[],minPassword:8,maxAttempts:5,lockMinutes:5,idleMinutes:30,maxHours:8};
const ACC_KEY="staff_accounts_v1", ATT_KEY="staff_attempts_v1", SES_KEY="staff_session_v1";
const PBKDF2_ITER=150000;
const jget=(st,k,d)=>{try{const v=st.getItem(k);return v?JSON.parse(v):d}catch(e){return d}};
const jset=(st,k,v)=>{try{st.setItem(k,JSON.stringify(v));return true}catch(e){return false}};
const jdel=(st,k)=>{try{st.removeItem(k)}catch(e){}};
const b64e=u8=>btoa(String.fromCharCode(...u8));
const b64d=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const randB64=n=>b64e(crypto.getRandomValues(new Uint8Array(n)));
const DUMMY_SALT="AAAAAAAAAAAAAAAAAAAAAA==";
const normEmail=s=>String(s||"").trim().toLowerCase();
const EMAIL_RE=/^[^\s@]+@[^\s@]+\.[^\s@]+$/;
let authNote="", signupOpened=Date.now(), prevPage="", lastTouch=0;

async function pbkdf2(pw,saltB64,iter){
  const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(pw),"PBKDF2",false,["deriveBits"]);
  const bits=await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt:b64d(saltB64),iterations:iter},key,256);
  return b64e(new Uint8Array(bits));
}
function same(a,b){
  if(a.length!==b.length) return false;
  let d=0; for(let i=0;i<a.length;i++) d|=a.charCodeAt(i)^b.charCodeAt(i);
  return d===0;
}

/* الجلسة: في ذاكرة التبويب فقط، تنتهي بعد خمول أو مدة قصوى */
function getSession(){
  const s=jget(sessionStorage,SES_KEY,null);
  if(s){
    const now=Date.now();
    if(now-s.last>AUTH.idleMinutes*60000||now-s.iat>AUTH.maxHours*3600000){
      jdel(sessionStorage,SES_KEY); authNote="انتهت الجلسة. سجّل الدخول من جديد.";
      return PSESS;
    }
    return s;
  }
  return PSESS;
}
const isAdmin=()=>{const s=getSession();return !!s&&s.role==="admin";};
function startSession(acc){
  const now=Date.now();
  jset(sessionStorage,SES_KEY,{tok:randB64(16),email:acc.email,name:acc.name,role:acc.role,iat:now,last:now});
}
function touch(){
  const now=Date.now(); if(now-lastTouch<15000) return; lastTouch=now;
  const s=jget(sessionStorage,SES_KEY,null); if(s){s.last=now;jset(sessionStorage,SES_KEY,s);}
}
["click","keydown","pointerdown","scroll"].forEach(ev=>addEventListener(ev,touch,{passive:true}));
setInterval(()=>{
  if(!jget(sessionStorage,SES_KEY,null)) return;
  getSession();
  if(!jget(sessionStorage,SES_KEY,null)) route();
},30000);

/* كلمة المرور */
function pwProblems(pw,email){
  const p=[], local=(email||"").split("@")[0];
  if(pw.length<AUTH.minPassword) p.push(AUTH.minPassword+" أحرف على الأقل");
  if(!/[A-Za-z؀-ۿ]/.test(pw)) p.push("حرف واحد على الأقل");
  if(!/\d/.test(pw)) p.push("رقم واحد على الأقل");
  if(local.length>=3&&pw.toLowerCase().includes(local)) p.push("لا تضمّن جزءًا من بريدك");
  return p;
}
function pwScore(pw){
  let s=0;
  if(pw.length>=8)s++; if(pw.length>=12)s++;
  if(/[A-Z]/.test(pw)&&/[a-z]/.test(pw))s++;
  if(/\d/.test(pw))s++; if(/[^A-Za-z0-9]/.test(pw))s++;
  return s;
}
const authMsg=(id,t,ok)=>{const m=$("#"+id); if(!m) return; m.textContent=t||""; m.classList.toggle("ok",!!ok);};
const cryptoOk=()=>!!(window.crypto&&crypto.subtle&&crypto.getRandomValues);

async function doSignup(){
  authMsg("suMsg","");
  if($("#suWeb").value) return;
  if(Date.now()-signupOpened<2500){authMsg("suMsg","أعد المحاولة بعد لحظات.");return;}
  const name=$("#suName").value.trim(), email=normEmail($("#suEmail").value), pw=$("#suPass").value, pw2=$("#suPass2").value;
  if(name.length<3){authMsg("suMsg","اكتب اسمك الكامل.");return;}
  if(!EMAIL_RE.test(email)){authMsg("suMsg","أدخل بريدًا إلكترونيًّا صحيحًا.");return;}
  if(AUTH.allowedDomains.length&&!AUTH.allowedDomains.some(d=>email.endsWith("@"+d.toLowerCase()))){authMsg("suMsg","استخدم بريدك الجامعي ("+AUTH.allowedDomains.join("، ")+").");return;}
  const pr=pwProblems(pw,email); if(pr.length){authMsg("suMsg","كلمة المرور تحتاج: "+pr.join("، ")+".");return;}
  if(pw!==pw2){authMsg("suMsg","كلمتا المرور غير متطابقتين.");return;}
  if(!cryptoOk()){authMsg("suMsg","هذا المتصفح لا يدعم التشفير المطلوب. افتح الصفحة عبر https.");return;}
  const accs=jget(localStorage,ACC_KEY,[]);
  if(accs.some(a=>a.email===email)){authMsg("suMsg","هذا البريد مسجّل بالفعل.");return;}
  const btn=$("#suBtn"); btn.disabled=true;
  try{
    const salt=randB64(16), hash=await pbkdf2(pw,salt,PBKDF2_ITER);
    const role=(AUTH.adminEmails.map(normEmail).includes(email)||!accs.length)?"admin":"staff";
    const acc={email,name,role,salt,iter:PBKDF2_ITER,hash,created:new Date().toISOString()};
    accs.push(acc);
    if(!jset(localStorage,ACC_KEY,accs)){authMsg("suMsg","تعذر حفظ الحساب في هذا المتصفح.");return;}
    startSession(acc);
    ["suName","suEmail","suPass","suPass2"].forEach(i=>{$("#"+i).value="";});
    $("#meterBar").style.width="0";
    location.hash=role==="admin"?"#home":"#form"; route();
  } finally {btn.disabled=false;}
}
async function doLogin(){
  authMsg("liMsg","");
  const email=normEmail($("#liEmail").value), pw=$("#liPass").value;
  if(!EMAIL_RE.test(email)||!pw){authMsg("liMsg","أدخل البريد وكلمة المرور.");return;}
  if(!cryptoOk()){authMsg("liMsg","هذا المتصفح لا يدعم التشفير المطلوب. افتح الصفحة عبر https.");return;}
  const att=jget(localStorage,ATT_KEY,{}), a=att[email]||{n:0,until:0};
  if(a.until>Date.now()){authMsg("liMsg","تم إيقاف المحاولات مؤقتًا. حاول بعد "+Math.ceil((a.until-Date.now())/60000)+" دقيقة.");return;}
  const btn=$("#liBtn"); btn.disabled=true;
  try{
    const acc=jget(localStorage,ACC_KEY,[]).find(x=>x.email===email);
    const h=await pbkdf2(pw,acc?acc.salt:DUMMY_SALT,acc?acc.iter:PBKDF2_ITER);
    if(acc&&same(h,acc.hash)){
      delete att[email]; jset(localStorage,ATT_KEY,att);
      startSession(acc); $("#liPass").value=""; $("#liEmail").value="";
      location.hash=acc.role==="admin"?"#home":"#form"; route(); return;
    }
    a.n++; if(a.n>=AUTH.maxAttempts){a.until=Date.now()+AUTH.lockMinutes*60000;a.n=0;}
    att[email]=a; jset(localStorage,ATT_KEY,att);
    authMsg("liMsg","البريد أو كلمة المرور غير صحيحة.");
  } finally {btn.disabled=false;}
}
function logout(){jdel(sessionStorage,SES_KEY);authNote="";location.hash="#login";route();}

function renderAuthUI(){
  const s=getSession();
  $$("[data-auth]").forEach(el=>{
    let show=el.dataset.auth==="in"?!!s:!s;
    if(show&&el.dataset.role==="admin"&&!isAdmin()) show=false;
    if(show&&el.id==="logout"&&s&&s.platform) show=false;
    el.hidden=!show;
  });
  const w=$("#who"); if(w) w.textContent=s?(s.name||s.email||""):"";
}

$("#loginForm").addEventListener("submit",e=>{e.preventDefault();doLogin().catch(()=>authMsg("liMsg","تعذر تنفيذ الطلب. حاول مرة أخرى."));});
$("#signupForm").addEventListener("submit",e=>{e.preventDefault();doSignup().catch(()=>authMsg("suMsg","تعذر تنفيذ الطلب. حاول مرة أخرى."));});
$$(".pwt").forEach(b=>b.addEventListener("click",()=>{
  const i=$("#"+b.dataset.for); i.type=i.type==="password"?"text":"password";
  b.textContent=i.type==="password"?"إظهار":"إخفاء";
}));
$("#suPass").addEventListener("input",()=>{
  const sc=pwScore($("#suPass").value), bar=$("#meterBar");
  bar.style.width=($("#suPass").value?Math.max(10,sc/5*100):0)+"%";
  bar.style.background=sc<=2?"var(--err)":sc===3?"var(--orange)":"var(--ok)";
});
$("#logout").addEventListener("click",logout);

