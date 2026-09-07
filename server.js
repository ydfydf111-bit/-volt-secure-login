import express from "express";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3";
import argon2 from "argon2";
import { rateLimit } from "express-rate-limit";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === "production";
const FRONTEND_URL = process.env.FRONTEND_URL || "";

const db = new Database(path.join(__dirname, "users.db"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT NOT NULL UNIQUE,
 email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 is_admin INTEGER NOT NULL DEFAULT 0,
 email_verified INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sessions(
 id TEXT PRIMARY KEY,
 user_id INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS password_resets(
 token_hash TEXT PRIMARY KEY,
 user_id INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS email_verifications(
 token_hash TEXT PRIMARY KEY,
 user_id INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
`);

app.disable("x-powered-by");
app.use((req,res,next)=>{
  res.setHeader("X-Content-Type-Options","nosniff");
  res.setHeader("X-Frame-Options","DENY");
  res.setHeader("Referrer-Policy","strict-origin-when-cross-origin");
  next();
});
app.use(express.json({limit:"20kb"}));
app.use(express.urlencoded({extended:false,limit:"20kb"}));

const authLimiter = rateLimit({
 windowMs:15*60*1000, limit:10, standardHeaders:"draft-8", legacyHeaders:false,
 message:{error:"Too many attempts. Try again later."}
});
const registerLimiter = rateLimit({
 windowMs:60*60*1000, limit:5, standardHeaders:"draft-8", legacyHeaders:false,
 message:{error:"Too many registrations. Try again later."}
});

const normalizeEmail = e => String(e||"").trim().toLowerCase();
const validEmail = e => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
const validUsername = u => /^[a-zA-Z0-9_]{3,30}$/.test(u);

function cookie(res, token, maxAge){
  let s=`session=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`;
  if(isProduction) s+="; Secure";
  res.setHeader("Set-Cookie",s);
}
function clearCookie(res){ res.setHeader("Set-Cookie","session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"); }
function getCookie(req,name){
  const raw=req.headers.cookie||"";
  for(const part of raw.split(";")){
    const [k,...v]=part.trim().split("=");
    if(k===name) return decodeURIComponent(v.join("="));
  }
  return null;
}
function token(){
  return crypto.randomBytes(32).toString("base64url");
}
function hashToken(t){ return crypto.createHash("sha256").update(t).digest("hex"); }

function createSession(userId){
  const t=token(), expires=Date.now()+7*86400000;
  db.prepare("INSERT INTO sessions(id,user_id,expires_at) VALUES(?,?,?)").run(t,userId,expires);
  return {t,expires};
}
function auth(req,res,next){
  const t=getCookie(req,"session");
  if(!t) return res.status(401).json({error:"Not logged in."});
  const u=db.prepare(`
    SELECT s.id,s.expires_at,u.id AS user_id,u.username,u.email,u.is_admin,u.email_verified
    FROM sessions s JOIN users u ON u.id=s.user_id
    WHERE s.id=? AND s.expires_at>?
  `).get(t,Date.now());
  if(!u){clearCookie(res);return res.status(401).json({error:"Session expired."});}
  req.user=u; req.sessionToken=t; next();
}
function admin(req,res,next){
  if(!req.user?.is_admin) return res.status(403).json({error:"Admin only."});
  next();
}

// Registration
app.post("/api/register",registerLimiter,async(req,res)=>{
  try{
    const username=String(req.body.username||"").trim();
    const email=normalizeEmail(req.body.email);
    const password=String(req.body.password||"");
    if(!validUsername(username)) return res.status(400).json({error:"Username: 3-30 letters, numbers or _."});
    if(!validEmail(email)) return res.status(400).json({error:"Enter a valid email."});
    if(password.length<12) return res.status(400).json({error:"Password must be at least 12 characters."});
    if(db.prepare("SELECT id FROM users WHERE username=? OR email=?").get(username,email))
      return res.status(409).json({error:"Username or email already exists."});
    const hash=await argon2.hash(password,{type:argon2.argon2id});
    const info=db.prepare("INSERT INTO users(username,email,password_hash) VALUES(?,?,?)").run(username,email,hash);
    const {t,expires}=createSession(info.lastInsertRowid); cookie(res,t,7*86400);
    res.status(201).json({ok:true,message:"Account created.",user:{username,email}});
  }catch(e){console.error("register:",e.message);res.status(500).json({error:"Server error."});}
});

// Login
app.post("/api/login",authLimiter,async(req,res)=>{
  try{
    const email=normalizeEmail(req.body.email), password=String(req.body.password||"");
    const u=db.prepare("SELECT * FROM users WHERE email=?").get(email);
    if(!u || !(await argon2.verify(u.password_hash,password)))
      return res.status(401).json({error:"Invalid email or password."});
    const {t,expires}=createSession(u.id); cookie(res,t,7*86400);
    res.json({ok:true,user:{username:u.username,email:u.email,isAdmin:!!u.is_admin,emailVerified:!!u.email_verified}});
  }catch(e){console.error("login:",e.message);res.status(500).json({error:"Server error."});}
});

app.get("/api/me",auth,(req,res)=>res.json({
 loggedIn:true,user:{id:req.user.user_id,username:req.user.username,email:req.user.email,
 isAdmin:!!req.user.is_admin,emailVerified:!!req.user.email_verified}
}));

app.post("/api/logout",(req,res)=>{
 const t=getCookie(req,"session"); if(t) db.prepare("DELETE FROM sessions WHERE id=?").run(t);
 clearCookie(res); res.json({ok:true});
});

// Profile
app.patch("/api/profile",auth,async(req,res)=>{
 const username=String(req.body.username||"").trim();
 if(!validUsername(username)) return res.status(400).json({error:"Invalid username."});
 const exists=db.prepare("SELECT id FROM users WHERE username=? AND id<>?").get(username,req.user.user_id);
 if(exists) return res.status(409).json({error:"Username already exists."});
 db.prepare("UPDATE users SET username=? WHERE id=?").run(username,req.user.user_id);
 res.json({ok:true,username});
});

// Change password
app.post("/api/change-password",auth,async(req,res)=>{
 const oldP=String(req.body.oldPassword||""), newP=String(req.body.newPassword||"");
 const u=db.prepare("SELECT password_hash FROM users WHERE id=?").get(req.user.user_id);
 if(!await argon2.verify(u.password_hash,oldP)) return res.status(401).json({error:"Current password is incorrect."});
 if(newP.length<12) return res.status(400).json({error:"New password must be at least 12 characters."});
 const hash=await argon2.hash(newP,{type:argon2.argon2id});
 db.prepare("UPDATE users SET password_hash=? WHERE id=?").run(hash,req.user.user_id);
 db.prepare("DELETE FROM sessions WHERE user_id=? AND id<>?").run(req.user.user_id,req.sessionToken);
 res.json({ok:true,message:"Password changed. Other sessions were logged out."});
});

// Email verification: demo mode returns the link in JSON.
// In production, replace this with an email provider and NEVER expose the token in the UI.
app.post("/api/send-verification",auth,(req,res)=>{
 const raw=token(), h=hashToken(raw), expires=Date.now()+30*60*1000;
 db.prepare("DELETE FROM email_verifications WHERE user_id=?").run(req.user.user_id);
 db.prepare("INSERT INTO email_verifications(token_hash,user_id,expires_at) VALUES(?,?,?)").run(h,req.user.user_id,expires);
 const link=`${FRONTEND_URL||`http://localhost:${PORT}`}/verify-email.html?token=${encodeURIComponent(raw)}`;
 console.log("DEV verification link:",link);
 res.json({ok:true,message:"Verification link generated. In production send it by email.",devLink:link});
});
app.get("/api/verify-email",(req,res)=>{
 const raw=String(req.query.token||""), row=db.prepare("SELECT user_id FROM email_verifications WHERE token_hash=? AND expires_at>?").get(hashToken(raw),Date.now());
 if(!row) return res.status(400).json({error:"Invalid or expired verification link."});
 db.prepare("UPDATE users SET email_verified=1 WHERE id=?").run(row.user_id);
 db.prepare("DELETE FROM email_verifications WHERE token_hash=?").run(hashToken(raw));
 res.json({ok:true,message:"Email verified."});
});

// Forgot/reset password
app.post("/api/forgot-password",authLimiter,(req,res)=>{
 const email=normalizeEmail(req.body.email);
 const u=db.prepare("SELECT id FROM users WHERE email=?").get(email);
 // Always generic response.
 const response={ok:true,message:"If that email exists, a reset link has been created."};
 if(!u) return res.json(response);
 const raw=token(), h=hashToken(raw), expires=Date.now()+15*60*1000;
 db.prepare("DELETE FROM password_resets WHERE user_id=?").run(u.id);
 db.prepare("INSERT INTO password_resets(token_hash,user_id,expires_at) VALUES(?,?,?)").run(h,u.id,expires);
 const link=`${FRONTEND_URL||`http://localhost:${PORT}`}/reset-password.html?token=${encodeURIComponent(raw)}`;
 console.log("DEV password reset link:",link);
 res.json({...response,devLink:link});
});
app.post("/api/reset-password",authLimiter,async(req,res)=>{
 const raw=String(req.body.token||""), p=String(req.body.password||"");
 if(p.length<12) return res.status(400).json({error:"Password must be at least 12 characters."});
 const row=db.prepare("SELECT user_id FROM password_resets WHERE token_hash=? AND expires_at>?").get(hashToken(raw),Date.now());
 if(!row) return res.status(400).json({error:"Invalid or expired reset token."});
 const hash=await argon2.hash(p,{type:argon2.argon2id});
 db.prepare("UPDATE users SET password_hash=? WHERE id=?").run(hash,row.user_id);
 db.prepare("DELETE FROM password_resets WHERE user_id=?").run(row.user_id);
 db.prepare("DELETE FROM sessions WHERE user_id=?").run(row.user_id);
 res.json({ok:true,message:"Password reset. You can log in now."});
});

// Admin dashboard APIs
app.get("/api/admin/users",auth,admin,(req,res)=>{
 const users=db.prepare("SELECT id,username,email,is_admin,email_verified,created_at FROM users ORDER BY id DESC").all();
 res.json({users});
});
app.patch("/api/admin/users/:id",auth,admin,(req,res)=>{
 const id=Number(req.params.id);
 if(id===req.user.user_id) return res.status(400).json({error:"Do not remove your own admin access here."});
 const isAdmin=req.body.isAdmin?1:0;
 db.prepare("UPDATE users SET is_admin=? WHERE id=?").run(isAdmin,id);
 res.json({ok:true});
});
app.delete("/api/admin/users/:id",auth,admin,(req,res)=>{
 const id=Number(req.params.id);
 if(id===req.user.user_id) return res.status(400).json({error:"You cannot delete yourself."});
 db.prepare("DELETE FROM users WHERE id=?").run(id);
 res.json({ok:true});
});

app.use(express.static(path.join(__dirname,"public")));
app.get("*splat",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));

app.listen(PORT,()=>console.log(`Volt running: http://localhost:${PORT}`));
