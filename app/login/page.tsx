"use client";
import { FormEvent, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
export default function LoginPage() {
  const router = useRouter();
  const [email,setEmail]=useState("");
  const [password,setPassword]=useState("");
  const [error,setError]=useState("");
  const [busy,setBusy]=useState(false);
  const [signup,setSignup]=useState(() => typeof window !== "undefined" && new URLSearchParams(window.location.search).get("signup")==="1");
  async function submit(e:FormEvent){e.preventDefault();setBusy(true);setError("");
    const r=await fetch(signup?"/api/auth/signup":"/api/auth/login",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({email,password})});
    const data=await r.json();setBusy(false);
    if(!r.ok){setError(data.error??"Login failed");return} router.replace("/");
  }
  return <main className="authPage"><form className="authCard" onSubmit={submit}><h1>Slot Simulator</h1><p>{signup?"Create your slot simulator account":"Sign in to continue"}</p><label>Email<input type="email" autoComplete="username" value={email} onChange={e=>setEmail(e.target.value)} required/></label><label>Password<input type="password" autoComplete="current-password" value={password} onChange={e=>setPassword(e.target.value)} required/></label>{error&&<div className="error">{error}</div>}<button disabled={busy}>{busy?(signup?"Creating account...":"Signing in..."):(signup?"Create account":"Sign in")}</button><button type="button" className="secondary" onClick={()=>{setSignup(!signup);setError("")}}>{signup?"Already have an account? Sign in":"Create an account"}</button></form></main>}