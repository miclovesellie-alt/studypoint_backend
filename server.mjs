import { createHash, createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { mkdir, readFile, rename, stat, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { basename, extname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const publicRoot = fileURLToPath(new URL('.', import.meta.url));
const dataRoot = resolve(process.env.STUDYPOINT_DATA_DIR || join(publicRoot, 'data'));
const uploadRoot = join(dataRoot, 'uploads');
const storeFile = join(dataRoot, 'store.json');
const port = Number(process.env.PORT || process.env.STUDYPOINT_PORT || 4173);
const host = process.env.STUDYPOINT_HOST || (process.env.PORT ? '0.0.0.0' : '127.0.0.1');
const allowedOrigin = (process.env.STUDYPOINT_ALLOWED_ORIGIN || '').replace(/\/$/,'');
const sessions = new Map();
const allowedExtensions = new Set(['.pdf', '.doc', '.docx', '.ppt', '.pptx', '.txt']);
const mimeTypes = { '.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.json':'application/json; charset=utf-8','.svg':'image/svg+xml' };

const defaultSettings = { starterCredits:10, rewardUploadCount:3, pricePerCreditGhs:10, currency:'GHS', uploadEnabled:true };
const adminEmail = (process.env.STUDYPOINT_ADMIN_EMAIL || 'boafokyei3@gmail.com').trim().toLowerCase();
const paystackSecretKey = process.env.PAYSTACK_SECRET_KEY || '';
const paystackWebhookSecret = process.env.PAYSTACK_WEBHOOK_SECRET || '';
const publicUrl = (process.env.STUDYPOINT_PUBLIC_URL || `http://${host}:${port}`).replace(/\/$/,'');
const frontendUrl = (process.env.STUDYPOINT_FRONTEND_URL || allowedOrigin || publicUrl).replace(/\/$/,'');
await mkdir(uploadRoot,{recursive:true});
let store;
try { store=JSON.parse(await readFile(storeFile,'utf8')); }
catch { store={ users:[], documents:[], reports:[], transactions:[], payments:[], settings:{...defaultSettings} }; }
store.users ||= [];
store.documents ||= [];
store.reports ||= [];
store.transactions ||= [];
store.payments ||= [];
store.settings={...defaultSettings,...(store.settings||{}),currency:'GHS'};
delete store.settings.pricePerCredit;
const removedDocumentIds=new Set(store.documents.filter(doc=>doc.source==='seed').map(doc=>doc.id));
store.documents=store.documents.filter(doc=>doc.source!=='seed');
for(const user of store.users){user.savedIds=(user.savedIds||[]).filter(id=>!removedDocumentIds.has(id));user.downloadedIds=(user.downloadedIds||[]).filter(id=>!removedDocumentIds.has(id));}
store.users=store.users.filter(user=>user.role!=='guest'&&!(user.role==='admin'&&user.email!==adminEmail));
store.reports=store.reports.filter(report=>!removedDocumentIds.has(report.documentId));
store.transactions=store.transactions.filter(tx=>tx.type!=='demo_purchase'&&!removedDocumentIds.has(tx.documentId));
store.payments=store.payments.filter(payment=>payment.userId&&store.users.some(user=>user.id===payment.userId));

function hashPassword(password,salt=randomBytes(16).toString('hex')){return {salt,hash:scryptSync(password,salt,64).toString('hex')};}
function verifyPassword(password,record){try{return timingSafeEqual(Buffer.from(scryptSync(password,record.salt,64).toString('hex'),'hex'),Buffer.from(record.hash,'hex'));}catch{return false;}}
function makeUser({email,name,role='member',password,credits=store.settings.starterCredits}){
  const auth=password?hashPassword(password):null;
  return {id:randomBytes(12).toString('hex'),email:email||null,name,role,credits,savedIds:[],downloadedIds:[],contributionCount:0,createdAt:new Date().toISOString(),...(auth?{salt:auth.salt,passwordHash:auth.hash}:{})};
}
if(process.env.STUDYPOINT_ADMIN_PASSWORD){
  const auth=hashPassword(process.env.STUDYPOINT_ADMIN_PASSWORD);
  let admin=store.users.find(user=>user.role==='admin')||userByEmail(adminEmail);
  if(!admin){admin=makeUser({email:adminEmail,name:'StudyPoint Admin',role:'admin',credits:0});store.users.push(admin);}
  admin.email=adminEmail;admin.name='StudyPoint Admin';admin.role='admin';admin.salt=auth.salt;admin.passwordHash=auth.hash;admin.credits=0;
  console.log(`Administrator password configured for ${adminEmail}`);
} else {
  const admin=store.users.find(user=>user.role==='admin');if(admin)admin.email=adminEmail;
  console.log('Administrator is not configured. Set STUDYPOINT_ADMIN_PASSWORD to enable admin sign-in.');
}
async function persist(){const tmp=`${storeFile}.tmp`;await writeFile(tmp,JSON.stringify(store,null,2),'utf8');await rename(tmp,storeFile);}
await persist();

function json(res,status,payload,headers={}){res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',...headers});res.end(JSON.stringify(payload));}
function fail(res,status,message){json(res,status,{error:message});}
function cookieMap(req){return Object.fromEntries((req.headers.cookie||'').split(';').map(part=>part.trim()).filter(Boolean).map(part=>{const i=part.indexOf('=');return [part.slice(0,i),decodeURIComponent(part.slice(i+1))];}));}
function sessionCookie(token,maxAge=60*60*24*30){const secure=publicUrl.startsWith('https://');return `sp_session=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=${secure?'None':'Lax'};${secure?' Secure;':''} Max-Age=${maxAge}`;}
function safeUser(user){return {id:user.id,name:user.name,email:user.email,role:user.role,credits:user.credits,savedIds:user.savedIds||[],downloadedIds:user.downloadedIds||[],contributionCount:user.contributionCount||0,createdAt:user.createdAt};}
function safeDoc(doc){const {hash,storageName,...safe}=doc;return safe;}
function startSession(user,res){const token=randomBytes(32).toString('base64url');sessions.set(token,user.id);res.setHeader('Set-Cookie',sessionCookie(token));return token;}
function getUser(req){const token=cookieMap(req).sp_session,userId=token?sessions.get(token):null;return store.users.find(candidate=>candidate.id===userId)||null;}
function requireUser(req,res){const user=getUser(req);if(!user)fail(res,401,'Sign in to continue.');return user;}
function requireAdmin(req,res){const user=requireUser(req,res);if(!user)return null;if(user.role!=='admin'){fail(res,403,'Admin access required. Sign in with an administrator account.');return null;}return user;}
async function readBody(req,max=1024*1024){const chunks=[];let size=0;for await(const chunk of req){size+=chunk.length;if(size>max){req.destroy();throw Object.assign(new Error('Request is too large.'),{status:413});}chunks.push(chunk);}return Buffer.concat(chunks);}
async function readJson(req,max){const data=await readBody(req,max);try{return data.length?JSON.parse(data.toString('utf8')):{};}catch{throw Object.assign(new Error('Invalid JSON body.'),{status:400});}}
function normalizeTitle(value){return String(value||'').toLocaleLowerCase().normalize('NFKD').replace(/[\u0300-\u036f]/g,'').replace(/[^a-z0-9]/g,'');}
function cleanFilename(value){return basename(String(value||'document').replace(/[\\/\0]/g,'_')).replace(/[^a-zA-Z0-9._ -]/g,'_').slice(0,120)||'document';}
function parseMultipart(buffer,boundary){const result={fields:{},file:null};const sep=`--${boundary}`;for(let part of buffer.toString('latin1').split(sep).slice(1,-1)){part=part.replace(/^\r\n/,'').replace(/\r\n$/,'');const split=part.indexOf('\r\n\r\n');if(split<0)continue;const headers=part.slice(0,split),body=part.slice(split+4).replace(/\r\n$/,'');const disp=headers.match(/content-disposition:\s*form-data;([^\r\n]+)/i)?.[1]||'';const name=disp.match(/name="([^"]+)"/)?.[1];const filename=disp.match(/filename="([^"]*)"/)?.[1];if(!name)continue;const value=Buffer.from(body,'latin1');if(filename){result.file={field:name,filename:cleanFilename(filename),buffer:value};}else result.fields[name]=value.toString('utf8');}return result;}
function attachmentName(name){return String(name).replace(/[\r\n"\\]/g,'_');}
function addTransaction({userId,type,credits,amount=0,currency='GHS',documentId=null,note=''}){store.transactions.unshift({id:randomBytes(10).toString('hex'),userId,type,credits,amount,currency,documentId,note,createdAt:new Date().toISOString()});}
function userByEmail(email){return store.users.find(user=>user.email&&user.email.toLowerCase()===String(email||'').toLowerCase());}
function binaryReply(res,status,buffer,filename,extension,extra={}){const types={'.pdf':'application/pdf','.doc':'application/msword','.docx':'application/vnd.openxmlformats-officedocument.wordprocessingml.document','.ppt':'application/vnd.ms-powerpoint','.pptx':'application/vnd.openxmlformats-officedocument.presentationml.presentation','.txt':'text/plain; charset=utf-8'};res.writeHead(status,{'Content-Type':types[extension]||'application/octet-stream','Content-Disposition':`attachment; filename="${attachmentName(filename)}"`,'Cache-Control':'no-store',...extra});res.end(buffer);}

function constantTimeHexEqual(actual,expected){if(typeof actual!=='string'||!/^[0-9a-f]{128}$/i.test(actual)||!/^[0-9a-f]{128}$/i.test(expected||''))return false;return timingSafeEqual(Buffer.from(actual,'hex'),Buffer.from(expected,'hex'));}
function validPaystackWebhook(raw,req){
  const current=req.headers['paystack-signature'];
  if(typeof current==='string'&&paystackWebhookSecret){
    let timestamp=null;const signatures=[];
    for(const part of current.split(',')){const [key,...value]=part.trim().split('=');if(key==='t')timestamp=value.join('=');if(key==='v1')signatures.push(value.join('=').split(':').at(-1));}
    const seconds=Number(timestamp);if(Number.isFinite(seconds)&&Math.abs(Date.now()/1000-seconds)<=300){const expected=createHmac('sha512',paystackWebhookSecret).update(`${timestamp}.`).update(raw).digest('hex');if(signatures.some(signature=>constantTimeHexEqual(signature,expected)))return true;}
  }
  const legacy=req.headers['x-paystack-signature'];
  return typeof legacy==='string'&&Boolean(paystackSecretKey)&&constantTimeHexEqual(legacy,createHmac('sha512',paystackSecretKey).update(raw).digest('hex'));
}
async function grantVerifiedPayment(payment,data){
  if(!payment||data?.status!=='success'||data.reference!==payment.reference||data.currency!=='GHS'||Number(data.amount)!==payment.amount)return false;
  if(payment.creditedAt)return true;
  const user=store.users.find(item=>item.id===payment.userId);if(!user)return false;
  user.credits+=payment.credits;payment.status='success';payment.creditedAt=new Date().toISOString();payment.processorId=String(data.id||'');payment.channel=String(data.channel||'');
  addTransaction({userId:user.id,type:'purchase',credits:payment.credits,amount:payment.amount/100,currency:'GHS',note:'Paystack payment verified'});
  await persist();return true;
}

async function handleApi(req,res,url){const path=url.pathname,method=req.method;
  if(method==='GET'&&path==='/api/health')return json(res,200,{ok:true,service:'StudyPoint API'});
  if(method==='GET'&&path==='/api/bootstrap'){const user=getUser(req);return json(res,200,{user:user?safeUser(user):null,documents:store.documents.filter(doc=>doc.status==='approved').map(safeDoc),settings:{...store.settings,paymentEnabled:Boolean(paystackSecretKey&&store.settings.pricePerCreditGhs>0)},uploads:user?store.documents.filter(doc=>doc.uploaderId===user.id).map(safeDoc):[]});}
  if(method==='POST'&&path==='/api/auth/register'){const body=await readJson(req);const email=String(body.email||'').trim().toLowerCase(),name=String(body.name||'').trim().slice(0,70),password=String(body.password||'');if(!name||!/^\S+@\S+\.\S+$/.test(email)||password.length<8)return fail(res,400,'Enter your name, a valid email, and a password with at least 8 characters.');if(userByEmail(email))return fail(res,409,'That email already has an account.');const user=makeUser({email,name,role:'member'}),auth=hashPassword(password);user.salt=auth.salt;user.passwordHash=auth.hash;store.users.push(user);startSession(user,res);await persist();return json(res,201,{user:safeUser(user)});}
  if(method==='POST'&&path==='/api/auth/login'){const body=await readJson(req);const user=userByEmail(body.email);if(!user||!user.passwordHash||!verifyPassword(String(body.password||''),{salt:user.salt,hash:user.passwordHash}))return fail(res,401,'Email or password is incorrect.');startSession(user,res);return json(res,200,{user:safeUser(user)});}
  if(method==='POST'&&path==='/api/auth/logout'){const token=cookieMap(req).sp_session;if(token)sessions.delete(token);res.setHeader('Set-Cookie',sessionCookie('',0));return json(res,200,{ok:true});}
  if(method==='POST'&&path==='/api/payments/initialize'){
    const user=requireUser(req,res);if(!user)return;if(!paystackSecretKey)return fail(res,503,'Paystack is not configured. Set PAYSTACK_SECRET_KEY on the server to enable checkout.');
    const price=Number(store.settings.pricePerCreditGhs);if(!Number.isFinite(price)||price<0.1)return fail(res,503,'Set a valid download price in Ghana cedis in Admin settings.');
    if(!user.email)return fail(res,400,'Add an email address to your account before purchasing a credit.');
    const reference=`sp-${randomBytes(16).toString('hex')}`,payment={reference,userId:user.id,credits:1,amount:Math.round(price*100),currency:'GHS',status:'initializing',createdAt:new Date().toISOString()};
    store.payments.unshift(payment);await persist();
    let processorResponse;
    try{processorResponse=await fetch('https://api.paystack.co/transaction/initialize',{method:'POST',headers:{Authorization:`Bearer ${paystackSecretKey}`,'Content-Type':'application/json'},body:JSON.stringify({email:user.email,amount:payment.amount,currency:'GHS',reference,callback_url:`${frontendUrl}/?payment=return`,metadata:{studyPointReference:reference,userId:user.id},cancel_action:`${frontendUrl}/?payment=cancelled`})});}
    catch{payment.status='initialization_failed';await persist();return fail(res,502,'Could not connect to Paystack. Try again.');}
    const result=await processorResponse.json().catch(()=>({}));
    if(!processorResponse.ok||!result.status||!result.data?.authorization_url){payment.status='initialization_failed';await persist();return fail(res,502,result.message||'Paystack could not start checkout. Try again.');}
    payment.status='pending';payment.accessCode=result.data.access_code||null;payment.initializedAt=new Date().toISOString();await persist();
    return json(res,200,{authorizationUrl:result.data.authorization_url,reference});
  }
  if(method==='POST'&&path==='/api/payments/verify'){
    const user=requireUser(req,res);if(!user)return;if(!paystackSecretKey)return fail(res,503,'Paystack verification is not configured on the server.');
    const body=await readJson(req),reference=String(body.reference||''),payment=store.payments.find(item=>item.reference===reference&&item.userId===user.id);if(!payment)return fail(res,404,'Payment reference not found.');
    if(payment.creditedAt)return json(res,200,{credits:user.credits,added:payment.credits});
    const response=await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,{headers:{Authorization:`Bearer ${paystackSecretKey}`}}).catch(()=>null);if(!response)return fail(res,502,'Could not verify payment with Paystack.');
    const result=await response.json().catch(()=>({}));if(!response.ok||!result.status)return fail(res,502,result.message||'Paystack verification failed.');
    if(!await grantVerifiedPayment(payment,result.data))return fail(res,402,'Payment is not successful or its amount does not match this order. No credit was added.');
    return json(res,200,{credits:user.credits,added:payment.credits});
  }
  if(method==='POST'&&path==='/api/paystack/webhook'){
    const raw=await readBody(req,1024*1024);if(!validPaystackWebhook(raw,req))return fail(res,401,'Invalid Paystack webhook signature.');
    let event;try{event=JSON.parse(raw.toString('utf8'));}catch{return fail(res,400,'Invalid webhook payload.');}
    if(event.event==='charge.success'){const payment=store.payments.find(item=>item.reference===event.data?.reference);if(payment)await grantVerifiedPayment(payment,event.data);}
    return json(res,200,{ok:true});
  }
  if(method==='POST'&&path==='/api/uploads'){const user=requireUser(req,res);if(!user)return;if(!store.settings.uploadEnabled)return fail(res,403,'Uploads are temporarily paused.');const contentType=req.headers['content-type']||'',boundary=contentType.match(/boundary=(?:"([^"]+)"|([^;]+))/i);if(!boundary)return fail(res,400,'A multipart document upload is required.');const buf=await readBody(req,21*1024*1024);const form=parseMultipart(buf,boundary[1]||boundary[2]);const title=String(form.fields.title||'').trim().slice(0,90),category=String(form.fields.category||''),description=String(form.fields.description||'').trim().slice(0,180),file=form.file;if(!title||!description||!['Business','Science','Technology','Humanities','Other'].includes(category)||form.fields.rightsConfirmed!=='true'||!file)return fail(res,400,'Complete all fields and confirm you have permission to share the document.');const ext=extname(file.filename).toLowerCase();if(!allowedExtensions.has(ext))return fail(res,400,'Use a PDF, Word, PowerPoint, or text document.');if(!file.buffer.length||file.buffer.length>20*1024*1024)return fail(res,400,'The document must be between 1 byte and 20 MB.');const hash=createHash('sha256').update(file.buffer).digest('hex');if(store.documents.some(doc=>doc.hash===hash||normalizeTitle(doc.title)===normalizeTitle(title)))return fail(res,409,'A matching document is already in the library or awaiting review.');const storageName=`${hash}${ext}`;await writeFile(join(uploadRoot,storageName),file.buffer,{flag:'wx'});const doc={id:`doc-${randomBytes(10).toString('hex')}`,title,category:category==='Other'?'Humanities':category,description,format:ext.slice(1).toUpperCase(),pages:null,author:user.name,initials:user.name.split(/\s+/).map(part=>part[0]).join('').slice(0,2).toUpperCase(),cover:['mint','blue','sand','lilac','rose','yellow'][store.documents.filter(item=>item.uploaderId===user.id).length%6],preview:null,status:'pending',source:'upload',uploaderId:user.id,originalName:file.filename,storageName,hash,size:file.buffer.length,createdAt:new Date().toISOString(),reviewedAt:null};store.documents.unshift(doc);await persist();return json(res,201,{document:safeDoc(doc),message:'Your document was submitted for review. Credits are awarded after approval.'});}
  const previewMatch=path.match(/^\/api\/documents\/([^/]+)\/preview$/);if(method==='GET'&&previewMatch){const id=decodeURIComponent(previewMatch[1]),doc=store.documents.find(item=>item.id===id&&item.status==='approved');if(!doc)return fail(res,404,'Document not found.');if(!doc.storageName||extname(doc.originalName).toLowerCase()!=='.txt')return json(res,200,{text:null,format:doc.format});const text=(await readFile(join(uploadRoot,doc.storageName))).toString('utf8').slice(0,2400);return json(res,200,{text,format:doc.format});}
  const saveMatch=path.match(/^\/api\/documents\/([^/]+)\/save$/);if(method==='POST'&&saveMatch){const user=requireUser(req,res);if(!user)return;const id=decodeURIComponent(saveMatch[1]),doc=store.documents.find(item=>item.id===id&&item.status==='approved');if(!doc)return fail(res,404,'Document not found.');user.savedIds ||= [];user.savedIds.includes(id)?user.savedIds=user.savedIds.filter(item=>item!==id):user.savedIds.push(id);await persist();return json(res,200,{savedIds:user.savedIds});}
  const downloadMatch=path.match(/^\/api\/documents\/([^/]+)\/download$/);if(method==='POST'&&downloadMatch){const user=requireUser(req,res);if(!user)return;const id=decodeURIComponent(downloadMatch[1]),doc=store.documents.find(item=>item.id===id&&item.status==='approved');if(!doc)return fail(res,404,'Document not found.');if(!doc.storageName)return fail(res,410,'The original document file is unavailable.');user.downloadedIds ||= [];const already=user.downloadedIds.includes(id);if(!already&&user.credits<1)return fail(res,402,'You are out of credits. Choose a credit to continue.');if(!already){user.credits--;user.downloadedIds.push(id);addTransaction({userId:user.id,type:'download',credits:-1,documentId:id,note:doc.title});await persist();}const buffer=await readFile(join(uploadRoot,doc.storageName)),filename=doc.originalName,extension=extname(filename).toLowerCase();return binaryReply(res,200,buffer,filename,extension,{'X-StudyPoint-Credits':String(user.credits),'X-StudyPoint-Already-Downloaded':already?'true':'false'});}
  if(method==='POST'&&path==='/api/reports'){const user=requireUser(req,res);if(!user)return;const body=await readJson(req),doc=store.documents.find(item=>item.id===body.documentId&&item.status==='approved');if(!doc)return fail(res,404,'Document not found.');if(!['Copyright concern','Incorrect or misleading','Poor quality','Private information','Other'].includes(body.reason))return fail(res,400,'Choose a report reason.');if(store.reports.some(report=>report.userId===user.id&&report.documentId===doc.id&&report.status==='open'))return fail(res,409,'You already reported this document.');const report={id:randomBytes(10).toString('hex'),documentId:doc.id,title:doc.title,userId:user.id,reason:body.reason,details:String(body.details||'').trim().slice(0,600),status:'open',createdAt:new Date().toISOString()};store.reports.unshift(report);await persist();return json(res,201,{report});}

  if(path.startsWith('/api/admin/')){const admin=requireAdmin(req,res);if(!admin)return;
    if(method==='GET'&&path==='/api/admin/summary'){const users=store.users.filter(user=>user.role==='member'),docs=store.documents;return json(res,200,{users:users.length,documents:docs.filter(doc=>doc.status==='approved').length,pending:docs.filter(doc=>doc.status==='pending').length,reports:store.reports.filter(report=>report.status==='open').length,downloads:store.transactions.filter(tx=>tx.type==='download').length,creditsOutstanding:users.reduce((sum,user)=>sum+user.credits,0)});}
    if(method==='GET'&&path==='/api/admin/documents'){return json(res,200,{documents:store.documents.map(doc=>({...safeDoc(doc),uploaderName:store.users.find(user=>user.id===doc.uploaderId)?.name||doc.author}))});}
    if(method==='GET'&&path==='/api/admin/users'){return json(res,200,{users:store.users.filter(user=>user.role==='member').map(safeUser)});}
    if(method==='GET'&&path==='/api/admin/reports'){return json(res,200,{reports:store.reports.map(report=>({...report,reporterName:store.users.find(user=>user.id===report.userId)?.name||'Member'}))});}
    if(method==='GET'&&path==='/api/admin/transactions'){return json(res,200,{transactions:store.transactions.slice(0,200).map(tx=>({...tx,userName:store.users.find(user=>user.id===tx.userId)?.name||'Member'}))});}
    if(method==='GET'&&path==='/api/admin/settings'){return json(res,200,{settings:{...store.settings,paymentEnabled:Boolean(paystackSecretKey)}});}
    const reviewMatch=path.match(/^\/api\/admin\/documents\/([^/]+)\/review$/);if(method==='POST'&&reviewMatch){const id=decodeURIComponent(reviewMatch[1]),doc=store.documents.find(item=>item.id===id),body=await readJson(req);if(!doc||doc.status!=='pending')return fail(res,404,'Pending document not found.');if(!['approve','reject'].includes(body.action))return fail(res,400,'Choose approve or reject.');doc.status=body.action==='approve'?'approved':'rejected';doc.reviewedAt=new Date().toISOString();doc.reviewedBy=admin.id;doc.reviewNote=String(body.note||'').trim().slice(0,400);if(doc.status==='approved'){const contributor=store.users.find(user=>user.id===doc.uploaderId);if(contributor){contributor.contributionCount=(contributor.contributionCount||0)+1;const threshold=Math.max(1,Number(store.settings.rewardUploadCount)||3);if(contributor.contributionCount%threshold===0){contributor.credits++;addTransaction({userId:contributor.id,type:'contribution_reward',credits:1,documentId:doc.id,note:`${threshold} approved contributions`});}}}await persist();return json(res,200,{document:safeDoc(doc),message:doc.status==='approved'?'Document approved.':'Document rejected.'});}
    const reportMatch=path.match(/^\/api\/admin\/reports\/([^/]+)\/status$/);if(method==='POST'&&reportMatch){const report=store.reports.find(item=>item.id===decodeURIComponent(reportMatch[1])),body=await readJson(req);if(!report)return fail(res,404,'Report not found.');if(!['resolved','dismissed'].includes(body.status))return fail(res,400,'Choose resolved or dismissed.');report.status=body.status;report.reviewedAt=new Date().toISOString();report.reviewedBy=admin.id;await persist();return json(res,200,{report});}
    const creditMatch=path.match(/^\/api\/admin\/users\/([^/]+)\/credits$/);if(method==='POST'&&creditMatch){const target=store.users.find(user=>user.id===decodeURIComponent(creditMatch[1])&&user.role!=='admin');if(!target)return fail(res,404,'Member not found.');const body=await readJson(req),amount=Math.max(1,Math.min(50,Math.trunc(Number(body.amount)||1)));target.credits+=amount;addTransaction({userId:target.id,type:'admin_adjustment',credits:amount,note:String(body.note||'Admin credit adjustment').slice(0,150)});await persist();return json(res,200,{user:safeUser(target)});}
    if(method==='PATCH'&&path==='/api/admin/settings'){const body=await readJson(req);if(body.starterCredits!==undefined)store.settings.starterCredits=Math.max(0,Math.min(100,Math.trunc(Number(body.starterCredits))));if(body.rewardUploadCount!==undefined)store.settings.rewardUploadCount=Math.max(1,Math.min(20,Math.trunc(Number(body.rewardUploadCount))));if(body.pricePerCreditGhs!==undefined){const price=Number(body.pricePerCreditGhs);if(!Number.isFinite(price)||price<0.1||price>10000)return fail(res,400,'Download price must be between GHS 0.10 and GHS 10,000.');store.settings.pricePerCreditGhs=Math.round(price*100)/100;}if(body.uploadEnabled!==undefined)store.settings.uploadEnabled=Boolean(body.uploadEnabled);await persist();return json(res,200,{settings:{...store.settings,paymentEnabled:Boolean(paystackSecretKey)}});}
    return fail(res,404,'Admin endpoint not found.');
  }
  return false;
}

const server=createServer(async(req,res)=>{
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('Referrer-Policy','same-origin');
  res.setHeader('X-Frame-Options','DENY');
  if(allowedOrigin&&req.headers.origin===allowedOrigin){res.setHeader('Access-Control-Allow-Origin',allowedOrigin);res.setHeader('Access-Control-Allow-Credentials','true');res.setHeader('Vary','Origin');}
  if(req.method==='OPTIONS'&&req.url?.startsWith('/api/')){res.writeHead(204,{'Access-Control-Allow-Methods':'GET,POST,PATCH,OPTIONS','Access-Control-Allow-Headers':'Content-Type'});return res.end();}
  let url;try{url=new URL(req.url,`http://${host}:${port}`);}catch{return fail(res,400,'Invalid request URL.');}
  if(url.pathname.startsWith('/api/')){try{const result=await handleApi(req,res,url);if(result!==false)return;return fail(res,404,'API endpoint not found.');}catch(error){if(!res.headersSent)fail(res,error.status||500,error.status?error.message:'The server could not complete that request.');else res.destroy();return;}}
  try{const pathname=decodeURIComponent(url.pathname),filePath=resolve(publicRoot,`.${pathname==='/'?'/index.html':pathname}`),rel=relative(publicRoot,filePath);if(rel.startsWith('..')||isAbsolute(rel))throw new Error('Outside app root.');const info=await stat(filePath);if(!info.isFile())throw new Error('Not a file.');res.writeHead(200,{'Content-Type':mimeTypes[extname(filePath)]||'application/octet-stream','Cache-Control':'no-store'});createReadStream(filePath).pipe(res);}catch{res.writeHead(404,{'Content-Type':'text/plain; charset=utf-8'});res.end('Not found');}
});
server.listen(port,host,()=>console.log(`StudyPoint running at http://${host}:${port}`));

