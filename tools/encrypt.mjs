#!/usr/bin/env node
// Encrypts every .html page in private/ into teacher/ (password-protected).
//
//   node tools/encrypt.mjs                 encrypt only
//   node tools/encrypt.mjs --publish       encrypt, commit and push to GitHub
//   node tools/encrypt.mjs --new-password  choose a new password
//
// The password is asked in the terminal (or read from TEACHER_PASSWORD).
// Encryption: PBKDF2-SHA256 (600k iterations) -> AES-256-GCM, decrypted in the
// browser with the Web Crypto API. Only encrypted files ever leave this computer.

import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import { join, dirname, relative, extname } from "node:path";
import { fileURLToPath } from "node:url";
import { webcrypto, randomBytes } from "node:crypto";
import { execSync } from "node:child_process";

const subtle = webcrypto.subtle;
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SRC = join(ROOT, "private");
const OUT = join(ROOT, "teacher");
const CONFIG = join(ROOT, "tools", "teacher-config.json");
const ITERATIONS = 600000;
const CHECK_TEXT = "teacher-area-ok";

const args = new Set(process.argv.slice(2));
const b64 = (buf) => Buffer.from(buf).toString("base64");
const unb64 = (s) => new Uint8Array(Buffer.from(s, "base64"));

function ask(question) {
  return new Promise((resolve) => {
    const stdin = process.stdin;
    if (!stdin.isTTY) { console.error("No terminal available: set TEACHER_PASSWORD instead."); process.exit(1); }
    process.stdout.write(question);
    stdin.setRawMode(true); stdin.resume(); stdin.setEncoding("utf8");
    let value = "";
    const onData = (chunk) => {
      for (const ch of chunk) {
        if (ch === "\r" || ch === "\n") {
          stdin.setRawMode(false); stdin.pause(); stdin.off("data", onData);
          process.stdout.write("\n"); resolve(value); return;
        }
        if (ch === "\u0003") { process.stdout.write("\n"); process.exit(1); }
        if (ch === "\u007f" || ch === "\b") value = value.slice(0, -1);
        else value += ch;
      }
    };
    stdin.on("data", onData);
  });
}

async function deriveKey(password, salt, iterations) {
  const base = await subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
  return subtle.deriveKey({ name: "PBKDF2", salt, iterations, hash: "SHA-256" }, base,
    { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

async function encrypt(key, text) {
  const iv = randomBytes(12);
  const data = await subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(text));
  return { iv: b64(iv), data: b64(data) };
}

async function decrypt(key, { iv, data }) {
  const buf = await subtle.decrypt({ name: "AES-GCM", iv: unb64(iv) }, key, unb64(data));
  return new TextDecoder().decode(buf);
}

function listFiles(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? listFiles(join(dir, e.name)) : [join(dir, e.name)]);
}

function lockPage(payload, home) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow">
<title>Teacher's Area · Marianna Limone</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f5f7fb;color:#12263f;
  font-family:"Segoe UI",system-ui,-apple-system,Roboto,Arial,sans-serif}
.box{background:#fff;border:1px solid #dfe6f0;border-radius:14px;padding:28px;width:min(92vw,380px);box-shadow:0 10px 28px rgba(18,38,63,.1)}
h1{font-family:Georgia,serif;margin:0 0 6px;font-size:1.6rem}
p{color:#5b6b81;margin:0 0 16px;font-size:.95rem}
input[type=password]{width:100%;box-sizing:border-box;border:1px solid #dfe6f0;border-radius:10px;padding:10px 12px;font:inherit;margin-bottom:10px}
label{display:flex;gap:8px;align-items:center;font-size:.88rem;color:#5b6b81;margin-bottom:14px}
button{width:100%;background:#1f6fd6;color:#fff;border:none;border-radius:10px;padding:10px;font-weight:700;font-size:1rem;cursor:pointer}
button:disabled{opacity:.6;cursor:wait}
.err{color:#c62828;font-size:.88rem;min-height:1.2em;margin-top:10px}
a{color:#5b6b81;font-size:.85rem}
</style>
</head>
<body>
<noscript>Please enable JavaScript to open this page.</noscript>
<form class="box" id="lock" hidden>
  <h1>🔒 Teacher's Area</h1>
  <p>This page is reserved for teachers. Please enter the password.</p>
  <input type="password" id="pw" placeholder="Password" autocomplete="current-password" required autofocus>
  <label><input type="checkbox" id="remember" checked> Remember me on this device</label>
  <button id="go">Unlock</button>
  <div class="err" id="err"></div>
  <a href="${home}">← Back to the lessons</a>
</form>
<script>
const P=${JSON.stringify(payload)};
const KEY="teacherAreaKey";
const unb64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const b64=b=>btoa(String.fromCharCode(...new Uint8Array(b)));
async function open(key){
  const buf=await crypto.subtle.decrypt({name:"AES-GCM",iv:unb64(P.iv)},key,unb64(P.data));
  const html=new TextDecoder().decode(buf);
  document.open();document.write(html);document.close();
}
(async()=>{
  const saved=localStorage.getItem(KEY);
  if(saved){
    try{const k=await crypto.subtle.importKey("raw",unb64(saved),"AES-GCM",false,["decrypt"]);await open(k);return;}
    catch(e){localStorage.removeItem(KEY);}
  }
  document.getElementById("lock").hidden=false;
})();
document.getElementById("lock").addEventListener("submit",async e=>{
  e.preventDefault();
  const btn=document.getElementById("go"),err=document.getElementById("err");
  btn.disabled=true;btn.textContent="Unlocking…";err.textContent="";
  try{
    const base=await crypto.subtle.importKey("raw",new TextEncoder().encode(document.getElementById("pw").value),"PBKDF2",false,["deriveKey"]);
    const key=await crypto.subtle.deriveKey({name:"PBKDF2",salt:unb64(P.salt),iterations:P.iter,hash:"SHA-256"},base,{name:"AES-GCM",length:256},true,["decrypt"]);
    await crypto.subtle.decrypt({name:"AES-GCM",iv:unb64(P.iv)},key,unb64(P.data));
    if(document.getElementById("remember").checked)localStorage.setItem(KEY,b64(await crypto.subtle.exportKey("raw",key)));
    await open(key);
  }catch(x){
    err.textContent="Wrong password, please try again.";
    btn.disabled=false;btn.textContent="Unlock";
  }
});
</script>
</body>
</html>
`;
}

async function main() {
  if (!existsSync(SRC)) { console.error("Folder private/ not found."); process.exit(1); }

  let config = existsSync(CONFIG) ? JSON.parse(readFileSync(CONFIG, "utf8")) : null;
  const newPassword = !config || args.has("--new-password");
  const fromEnv = process.env.TEACHER_PASSWORD;

  let password = fromEnv ?? await ask(newPassword ? "Choose the Teacher's Area password: " : "Teacher's Area password: ");
  if (!password) { console.error("Empty password."); process.exit(1); }

  let key;
  if (newPassword) {
    if (!fromEnv && password !== await ask("Repeat the password: ")) { console.error("The passwords don't match."); process.exit(1); }
    if (password.length < 10) console.warn("⚠ Tip: a longer password (10+ characters) is much safer.");
    const salt = randomBytes(16);
    key = await deriveKey(password, salt, ITERATIONS);
    config = { salt: b64(salt), iterations: ITERATIONS, check: await encrypt(key, CHECK_TEXT) };
    writeFileSync(CONFIG, JSON.stringify(config, null, 2) + "\n");
  } else {
    key = await deriveKey(password, unb64(config.salt), config.iterations);
    try { await decrypt(key, config.check); }
    catch { console.error("✗ Wrong password (it doesn't match the one used before).\n  To change it, run: node tools/encrypt.mjs --new-password"); process.exit(1); }
  }

  rmSync(OUT, { recursive: true, force: true });
  let count = 0;
  for (const file of listFiles(SRC)) {
    const rel = relative(SRC, file);
    if (extname(file).toLowerCase() !== ".html") {
      if (!rel.endsWith(".DS_Store")) console.warn(`⚠ Skipped (only .html pages are encrypted): private/${rel}`);
      continue;
    }
    const enc = await encrypt(key, readFileSync(file, "utf8"));
    const out = join(OUT, rel);
    mkdirSync(dirname(out), { recursive: true });
    const home = "../".repeat(rel.split(/[\\/]/).length) + "index.html";
    writeFileSync(out, lockPage({ salt: config.salt, iter: config.iterations, ...enc }, home));
    console.log(`🔒 private/${rel} → teacher/${rel}`);
    count++;
  }
  console.log(`✔ ${count} page(s) encrypted.`);

  if (args.has("--publish")) {
    const run = (cmd) => execSync(cmd, { cwd: ROOT, stdio: "inherit" });
    run("git add -A teacher tools/teacher-config.json");
    const staged = execSync("git diff --cached --name-only", { cwd: ROOT }).toString().trim();
    if (staged) run('git commit -q -m "Update Teacher\'s Area"');
    run("git push -q");
    console.log("✔ Published. The site updates in about a minute.");
  }
}

main();
