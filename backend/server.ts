import http from "node:http";
import fs from "node:fs";
import pathModule from "node:path";
import { randomUUID } from "node:crypto";
import { MongoClient, ObjectId } from "mongodb";
import { defaultSlot } from "../lib/slot/default";
import type { SlotConfig } from "../lib/slot/types";
import { calculateMath } from "../lib/slot/math";
import bcrypt from "bcryptjs";
import crypto from "node:crypto";

const PORT=Number(process.env.SLOT_SERVER_PORT||4000);
const uri=process.env.MONGODB_URI;if(!uri)throw new Error("MONGODB_URI is required");
const mongo=new MongoClient(uri);
const listeners=new Map<string,Set<http.ServerResponse>>();
let db: ReturnType<MongoClient["db"]>;

async function session(req:http.IncomingMessage){const token=(req.headers.cookie||"").match(/(?:^|;\s*)slot_session=([^;]+)/)?.[1];if(!token)return null;const session=await db.collection("sessions").findOne<{token:string;userId:string;expiresAt:Date}>({token,expiresAt:{$gt:new Date()}});if(!session)return null;const uid=ObjectId.isValid(String(session.userId))?new ObjectId(String(session.userId)):String(session.userId);const user=await db.collection("users").findOne<any>({_id:uid});if(!user)return null;return {...session,userId:session.userId,role:user.role||"user"}}
async function json(req:http.IncomingMessage){let s="";for await(const x of req)s+=x;return s?JSON.parse(s):{}}
function send(res:http.ServerResponse,status:number,data:unknown){res.writeHead(status,{"content-type":"application/json","cache-control":"no-store"});res.end(JSON.stringify(data))}
function filter(id:string,userId:ObjectId|string){return ObjectId.isValid(id)?{_id:new ObjectId(id),userId}:{_id:id,userId}}
function emit(id:string,data:unknown){const set=listeners.get(id);if(!set)return;const packet=`event: spin\ndata: ${JSON.stringify(data)}\n\n`;for(const res of set)try{res.write(packet)}catch{set.delete(res)}}
function spin(c:SlotConfig){const grid=c.reels.map(r=>{const i=Math.floor(Math.random()*r.strip.length);return[0,1,2].map(n=>r.strip[(i+n)%r.strip.length])});let win=0,scatter=0;for(const reel of grid)for(const symbol of reel)if(symbol===c.freeSpins.triggerSymbol)scatter++;for(const line of c.paylines){const seq=line.rows.map((row,i)=>grid[i][row]);const wild=c.symbols.find(s=>s.type==="wild")?.id;let target=seq[0];if(wild&&target===wild)target=seq.find(s=>s!==wild)??wild;let count=0;for(const symbol of seq){if(symbol===target||symbol===wild)count++;else break}if(count>=3)win+=c.paytable[target]?.[String(count)]??0}return{grid,win,scatter}}
async function start(){ await mongo.connect(); db=mongo.db(process.env.MONGODB_DB||"slot_simulator"); const server=http.createServer(async(req,res)=>{
  const origin=req.headers.origin;
  const allowedOrigins=new Set(["http://localhost","http://localhost:3000","http://localhost:3001"]);
  if(origin&&allowedOrigins.has(origin)){res.setHeader("Access-Control-Allow-Origin",origin);res.setHeader("Vary","Origin");res.setHeader("Access-Control-Allow-Credentials","true");res.setHeader("Access-Control-Allow-Headers","Content-Type");res.setHeader("Access-Control-Allow-Methods","GET,POST,PUT,DELETE,OPTIONS");}
  if(req.method==="OPTIONS"){res.writeHead(204);return res.end();}
  try{
    const u=new URL(req.url||"/","http://localhost");const routePath=u.pathname;
    if(routePath==="/api/auth/signup"&&req.method==="POST"){
      const body=await json(req);const email=String(body.email||"").toLowerCase().trim();const password=String(body.password||"");
      if(!email||!password)return send(res,400,{error:"Email and password are required"});
      if(password.length<8)return send(res,400,{error:"Password must be at least 8 characters"});
      const users=db.collection("users");if(await users.findOne({email}))return send(res,409,{error:"User already exists"});
      const passwordHash=await bcrypt.hash(password,12);const result=await users.insertOne({email,passwordHash,role:"user",createdAt:new Date()});
      const config=structuredClone(defaultSlot);config.name="My Slot Machine";const now=new Date();
      await db.collection("slot_machines").insertOne({userId:result.insertedId,name:config.name,config,createdAt:now,updatedAt:now});
      const token=crypto.randomBytes(32).toString("hex");await db.collection("sessions").insertOne({token,userId:String(result.insertedId),createdAt:now,expiresAt:new Date(Date.now()+12*60*60*1000)});
      res.setHeader("Set-Cookie",`slot_session=${token}; HttpOnly; Path=/; Max-Age=43200; SameSite=Lax${process.env.NODE_ENV==="production"?"; Secure":""}`);
      return send(res,200,{ok:true,email,role:"user"});
    }
    if(routePath==="/api/auth/login"&&req.method==="POST"){
      const body=await json(req);const email=String(body.email||"").toLowerCase().trim();const password=String(body.password||"");
      if(!email||!password)return send(res,400,{error:"Email and password are required"});
      const users=db.collection("users");let user=await users.findOne<any>({email});
      const adminEmail=process.env.ADMIN_EMAIL?.toLowerCase().trim();const adminPassword=process.env.ADMIN_PASSWORD;
      if(!user&&adminEmail&&adminPassword&&email===adminEmail&&password===adminPassword){const passwordHash=await bcrypt.hash(adminPassword,12);const result=await users.insertOne({email:adminEmail,passwordHash,role:"admin",createdAt:new Date()});user={_id:result.insertedId,email:adminEmail,role:"admin",passwordHash}}
      if(!user||!(await bcrypt.compare(password,user.passwordHash)))return send(res,401,{error:"Invalid credentials"});
      const token=crypto.randomBytes(32).toString("hex");await db.collection("sessions").insertOne({token,userId:String(user._id),createdAt:new Date(),expiresAt:new Date(Date.now()+12*60*60*1000)});
      res.setHeader("Set-Cookie",`slot_session=${token}; HttpOnly; Path=/; Max-Age=43200; SameSite=Lax${process.env.NODE_ENV==="production"?"; Secure":""}`);
      return send(res,200,{ok:true,email:user.email,role:user.role});
    }
    if(routePath==="/api/auth/logout"&&req.method==="POST"){const token=(req.headers.cookie||"").match(/(?:^|;\s*)slot_session=([^;]+)/)?.[1];if(token)await db.collection("sessions").deleteOne({token});res.setHeader("Set-Cookie","slot_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax"+(process.env.NODE_ENV==="production"?"; Secure":""));return send(res,200,{ok:true})}
    if(routePath==="/api/auth/me"&&req.method==="GET"){const me=await session(req);if(!me)return send(res,401,{authenticated:false});return send(res,200,{authenticated:true,user:{email:(await db.collection("users").findOne<any>({_id:ObjectId.isValid(String(me.userId))?new ObjectId(String(me.userId)):String(me.userId)}))?.email,role:me.role}})}
    if(routePath==="/login"){
      const signup=new URL(req.url||"/login","http://localhost").searchParams.get("signup")==="1";
      const html=`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Slot Simulator</title><style>body{margin:0;font-family:system-ui;background:radial-gradient(circle at 50% 40%,#241317,#090a0d 65%);color:#eee;display:grid;place-items:center;min-height:100vh}.card{width:min(390px,calc(100% - 32px));padding:30px;border:1px solid #343944;border-radius:18px;background:#15181f;box-shadow:0 25px 70px #0008;box-sizing:border-box}h1{margin:0 0 8px;text-align:center}p{text-align:center;color:#9ba3b5}label{display:block;margin:16px 0 6px}input{width:100%;box-sizing:border-box;padding:12px;border-radius:9px;border:1px solid #444;background:#0e1015;color:#fff}button{margin-top:18px;width:100%;padding:12px;border:0;border-radius:9px;cursor:pointer;font-weight:700;background:#e34850;color:white}.secondary{background:#292d36}#error{color:#ff7272;margin-top:12px;text-align:center}</style></head><body><form class="card" id="f"><h1>🎰 Slot Simulator</h1><p id="mode">${signup?"Create your account":"Sign in to continue"}</p><label>Email</label><input id="email" type="email" required autocomplete="username"><label>Password</label><input id="password" type="password" minlength="8" required autocomplete="current-password"><button id="submitBtn">${signup?"Create account":"Sign in"}</button><button type="button" class="secondary" id="switch">${signup?"Already have an account? Sign in":"Create an account"}</button><div id="error"></div></form><script>let signup=${signup};const mode=document.getElementById("mode"),submitBtn=document.getElementById("submitBtn"),sw=document.getElementById("switch"),form=document.getElementById("f"),error=document.getElementById("error");sw.onclick=()=>{signup=!signup;history.replaceState(null,"",signup?"/login?signup=1":"/login");mode.textContent=signup?"Create your account":"Sign in to continue";submitBtn.textContent=signup?"Create account":"Sign in";sw.textContent=signup?"Already have an account? Sign in":"Create an account";error.textContent=""};form.onsubmit=async e=>{e.preventDefault();error.textContent="";const r=await fetch(signup?"/api/auth/signup":"/api/auth/login",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({email:email.value,password:password.value})});const d=await r.json();if(!r.ok){error.textContent=d.error||"Authentication failed";return}location.href="/"};</script></body></html>`;
      res.writeHead(200,{"content-type":"text/html; charset=utf-8","cache-control":"no-store"});return res.end(html);
    }
    const publicMachineRoute=routePath.match(/^\/slot-api\/machines\/([^/]+)\/(slot-config|events|spin)$/);
    if(publicMachineRoute){
      const id=decodeURIComponent(publicMachineRoute[1]);const action=publicMachineRoute[2];
      const machine=await db.collection("slot_machines").findOne({_id:ObjectId.isValid(id)?new ObjectId(id):id});
      if(!machine)return send(res,404,{error:"Machine not found"});
      if(action==="spin"&&req.method==="POST"){const result={id:randomUUID(),machineId:id,timestamp:Date.now(),...spin(machine.config as SlotConfig)};emit(id,result);return send(res,200,result)}
      const publicSession=await session(req);if(!publicSession)return send(res,401,{error:"Unauthorized"});
      const publicUser=await db.collection("users").findOne<any>({_id:ObjectId.isValid(String(publicSession.userId))?new ObjectId(String(publicSession.userId)):String(publicSession.userId)});
      if(publicUser?.role!=="admin")return send(res,403,{error:"Admin only"});
      if(action==="slot-config"&&req.method==="GET"){const config=machine.config||{};return send(res,200,{machineId:id,name:machine.name,reels:config.reels||[],symbols:config.symbols||[],paytable:config.paytable||{},paylines:config.paylines||[],freeSpins:config.freeSpins||{},targetRtp:config.targetRtp??0.95})}
      if(action==="events"&&req.method==="GET"){res.writeHead(200,{"content-type":"text/event-stream","cache-control":"no-cache","connection":"keep-alive","access-control-allow-origin":origin||"*"});res.write(": connected\\n\\n");if(!listeners.has(id))listeners.set(id,new Set());listeners.get(id)!.add(res);req.on("close",()=>listeners.get(id)?.delete(res));return}
    }
    if(routePath==="/"||routePath==="/vanilla/"||routePath==="/vanilla/index.html"||routePath.startsWith("/vanilla/dist/")||routePath.startsWith("/dist/")){
      const file=routePath==="/"||routePath==="/vanilla/"||routePath==="/vanilla/index.html"?"vanilla/index.html":routePath.startsWith("/dist/")?"vanilla"+routePath:routePath.slice(1);
      const full=pathModule.resolve(process.cwd(),file);if(!fs.existsSync(full))return send(res,404,{error:"Static file not found"});
      const ext=pathModule.extname(full);const types:any={".html":"text/html; charset=utf-8",".js":"text/javascript; charset=utf-8",".css":"text/css; charset=utf-8"};res.writeHead(200,{"content-type":types[ext]||"application/octet-stream","cache-control":"no-cache"});return res.end(fs.readFileSync(full));
    }
    const path=u.pathname;const s=await session(req);if(!s)return send(res,401,{error:"Unauthorized"});const ownerId=ObjectId.isValid(String(s.userId))?new ObjectId(String(s.userId)):String(s.userId);
if(req.method==="GET"&&path==="/slot-api/machines"){const ms=await db.collection("slot_machines").find({userId:ownerId}).sort({updatedAt:-1}).toArray();return send(res,200,{machines:ms.map(x=>({id:String(x._id),name:x.name,active:listeners.has(String(x._id))})),activeId:ms[0]?String(ms[0]._id):"",config:ms[0]?.config})}
if(req.method==="POST"&&path==="/slot-api/math"){const c=await json(req) as SlotConfig;return send(res,200,calculateMath(c))}
if(req.method==="GET"&&path.startsWith("/slot-api/machines/")&&path.endsWith("/slot-config")){const id=path.split("/")[3];const machine=await db.collection("slot_machines").findOne({_id:new ObjectId(id)});if(!machine)return send(res,404,{error:"Machine not found"});const config=machine.config||{};return send(res,200,{machineId:id,name:machine.name,reels:config.reels||[],symbols:config.symbols||[],paytable:config.paytable||{},freeSpins:config.freeSpins||{},targetRtp:config.targetRtp??0.95})}
if(req.method==="POST"&&path==="/slot-api/machines"){const creator=await db.collection("users").findOne<any>({_id:ownerId});if(creator?.role!=="admin"){const count=await db.collection("slot_machines").countDocuments({userId:ownerId});if(count>=1)return send(res,403,{error:"User accounts can have only one slot machine"});}const b=await json(req);const config=structuredClone((b.config as SlotConfig)||defaultSlot);const name=String(b.name||config.name||"New Slot Machine").trim()||"New Slot Machine";config.name=name;const now=new Date();const result=await db.collection("slot_machines").insertOne({userId:ownerId,name,config,createdAt:now,updatedAt:now});return send(res,200,{ok:true,machine:{id:String(result.insertedId),name},config})}

let match=path.match(/^\/slot-api\/machines\/([^/]+)(?:\/(activate|events|spin|simulate))?$/);
if(match){const id=decodeURIComponent(match[1]);const action=match[2];const m=await db.collection("slot_machines").findOne(filter(id,ownerId));if(!m)return send(res,404,{error:"Machine not found"});
 if(req.method==="GET"&&!action)return send(res,200,{id:String(m._id),name:m.name,config:m.config,active:listeners.has(id)});
 if(req.method==="PUT"&&!action){const b=await json(req);if(!ObjectId.isValid(id))return send(res,400,{error:"Invalid machine id"});const config=b.config as SlotConfig;config.name=String(b.name||config.name||m.name);const now=new Date();await db.collection("slot_machines").updateOne(filter(id,s.userId),{$set:{name:config.name,config,updatedAt:now}});return send(res,200,{ok:true,updatedAt:now.toISOString()})}
 if(req.method==="DELETE"&&!action){if(s.role!=="admin")return send(res,403,{error:"Admin only"});if(!ObjectId.isValid(id))return send(res,400,{error:"Invalid machine id"});await db.collection("slot_machines").deleteOne(filter(id,s.userId));listeners.delete(id);return send(res,200,{ok:true})}
 if(req.method==="POST"&&action==="activate"){if(s.role!=="admin")return send(res,403,{error:"Admin only"});if(!listeners.has(id))listeners.set(id,new Set());return send(res,200,{ok:true,machineId:id,events:`/slot-api/machines/${id}/events`})}
 if(req.method==="GET"&&action==="events"){res.writeHead(200,{"content-type":"text/event-stream","cache-control":"no-cache","connection":"keep-alive","access-control-allow-origin":origin||"http://localhost"});res.write(": connected\n\n");if(!listeners.has(id))listeners.set(id,new Set());listeners.get(id)!.add(res);req.on("close",()=>listeners.get(id)?.delete(res));return}
 if(req.method==="POST"&&action==="spin"){const result={id:randomUUID(),machineId:id,timestamp:Date.now(),...spin(m.config as SlotConfig)};emit(id,result);return send(res,200,result)}
 if(req.method==="POST"&&action==="simulate"){const b=await json(req),c=m.config as SlotConfig,n=Math.min(10000000,Math.max(1000,Number(b.spins)||100000));let total=0,wins=0,max=0,triggers=0;for(let i=0;i<n;i++){const x=spin(c);total+=x.win;if(x.win>0){wins++;max=Math.max(max,x.win)}if(c.freeSpins.enabled&&x.scatter>=c.freeSpins.triggerCount)triggers++}const wager=n*c.betPerSpin;return send(res,200,{spins:n,wager,totalWin:total,rtp:wager?total/wager:0,winSpins:wins,hitFrequency:wins/n,averageWin:wins?total/wins:0,maxWin:max,freeSpinTriggers:triggers})}
}
return send(res,404,{error:"Not found"})}catch(e){console.error("slot-server:",e);send(res,500,{error:e instanceof Error?e.message:"Server error"})}});
const port = Number(process.env.PORT) || 4000;
server.listen(port, "0.0.0.0", () => console.log(`Slot server listening on http://0.0.0.0:${port}`)); }
start().catch(error=>{console.error("Failed to start slot server:",error);process.exit(1)});