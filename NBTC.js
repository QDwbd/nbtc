export default {
  async fetch(req, env) {
    const url = new URL(req.url)
    const role = await getRole(req, env)
    if (url.pathname === "/login" && req.method === "POST") return login(req, env)
    if (url.pathname === "/logout") return logout()
    if (url.pathname === "/img") {
      if (!role) return new Response("Forbidden", { status: 403 })
      return serveImage(req, env)
    }
    if (url.pathname === "/delete") {
      if (role !== "admin") return new Response("Forbidden", { status: 403 })
      return deleteImages(req, env)
    }
    if (req.method === "POST") {
      if (role !== "admin") return new Response("Forbidden", { status: 403 })
      return uploadImage(req, env)
    }
    if (!role) return loginPage()
    return renderPage(req, env, role === "admin")
  }
}
async function hmacSign(secret, data) {
  const enc = new TextEncoder()
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  )
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data))
  return btoa(String.fromCharCode(...new Uint8Array(sig)))
}
function base64Encode(obj) {
  const str = JSON.stringify(obj)
  const bytes = new TextEncoder().encode(str)
  let binary = ''
  bytes.forEach(b => binary += String.fromCharCode(b))
  return btoa(binary)
}
function base64Decode(str) {
  const binary = atob(str)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return JSON.parse(new TextDecoder().decode(bytes))
}
async function getRole(req, env) {
  const c = req.headers.get("cookie") || ""
  const m = c.match(/session=([^;]+)/)
  if (!m) return null
  const [body, sig] = m[1].split(".")
  if (!body || !sig) return null
  const expected = await hmacSign(env.SESSION_SECRET, body)
  if (sig !== expected) return null
  let payload
  try { payload = base64Decode(body) } catch { return null }
  if (Date.now() > payload.exp) return null
  return payload.role
}
async function login(req, env) {
  const form = await req.formData()
  const password = form.get("password")
  let role = null
  if (password === env.ADMIN_PASSWORD) role = "admin"
  if (password === env.VISITOR_PASSWORD) role = "visitor"
  if (!role) return new Response("Forbidden", { status: 403 })
  const payload = { role, exp: Date.now() + 7 * 864e5 }
  const body = base64Encode(payload)
  const sig = await hmacSign(env.SESSION_SECRET, body)
  return new Response(null, {
    status: 302,
    headers: {
      "Set-Cookie": `session=${body}.${sig}; Path=/; HttpOnly; Secure; SameSite=Strict`,
      "Location": "/"
    }
  })
}
function logout() {
  return new Response(null, {
    status: 302,
    headers: {
      "Set-Cookie": "session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict",
      "Location": "/"
    }
  })
}
async function getIndexMeta(env) {
  let meta = await env.IMAGE_KV.get("INDEX:meta", "json")
  if (!meta) {
    meta = { count: 0, pageSize: 200 }
    await env.IMAGE_KV.put("INDEX:meta", JSON.stringify(meta))
  }
  return meta
}
async function cascadeOverflow(env, pageNum, id, meta) {
  const key = `INDEX:page:${pageNum}`
  const page = (await env.IMAGE_KV.get(key, "json")) || []
  page.unshift(id)
  if (page.length > meta.pageSize) {
    const overflow = page.pop()
    await env.IMAGE_KV.put(key, JSON.stringify(page))
    await cascadeOverflow(env, pageNum + 1, overflow, meta)
  } else {
    await env.IMAGE_KV.put(key, JSON.stringify(page))
  }
}
async function addToIndex(env, id) {
  const meta = await getIndexMeta(env)
  const key = "INDEX:page:0"
  const page = (await env.IMAGE_KV.get(key, "json")) || []
  page.unshift(id)
  if (page.length > meta.pageSize) {
    const overflow = page.pop()
    await env.IMAGE_KV.put(key, JSON.stringify(page))
    await cascadeOverflow(env, 1, overflow, meta)
  } else {
    await env.IMAGE_KV.put(key, JSON.stringify(page))
  }
  meta.count++
  await env.IMAGE_KV.put("INDEX:meta", JSON.stringify(meta))
}
async function removeFromIndex(env, ids) {
  const meta = await getIndexMeta(env)
  let pageNum = 0
  while (true) {
    const key = `INDEX:page:${pageNum}`
    const page = await env.IMAGE_KV.get(key, "json")
    if (!page) break
    const filtered = page.filter(id => !ids.includes(id))
    if (filtered.length !== page.length) {
      await env.IMAGE_KV.put(key, JSON.stringify(filtered))
    }
    pageNum++
  }
  meta.count = Math.max(0, meta.count - ids.length)
  await env.IMAGE_KV.put("INDEX:meta", JSON.stringify(meta))
}
async function uploadImage(req, env) {
  const form = await req.formData()
  const file = form.get("file")
  if (!file) return new Response("No file", { status: 400 })
  const buf = await file.arrayBuffer()
  const tf = new FormData()
  tf.append("chat_id", env.GROUP_ID)
  tf.append("document", new Blob([buf]), file.name)
  const res = await fetch(
    `https://api.telegram.org/bot${env.BOT_TOKEN}/sendDocument`,
    { method: "POST", body: tf }
  )
  const data = await res.json()
  if (!data.ok) return new Response("Telegram error", { status: 500 })
  const id = crypto.randomUUID()
  const filePath = await getFilePath(data.result.document.file_id, env)
  await env.IMAGE_KV.put(
    `img:${id}`,
    JSON.stringify({ msgId: data.result.message_id, filePath })
  )
  await addToIndex(env, id)
  return new Response("ok")
}
async function getFilePath(fileId, env) {
  const res = await fetch(
    `https://api.telegram.org/bot${env.BOT_TOKEN}/getFile?file_id=${fileId}`
  )
  const data = await res.json()
  return data.result.file_path
}
async function serveImage(req, env) {
  const url = new URL(req.url)
  const id = url.searchParams.get("id")
  if (!id) return new Response("Not Found", { status: 404 })
  const ref = req.headers.get("referer")
  if (ref && !ref.startsWith(url.origin))
    return new Response("Forbidden", { status: 403 })
  const cache = caches.default
  const cacheKey = new Request(url.toString(), { method: "GET" })
  let res = await cache.match(cacheKey)
  if (res) return res
  const record = await env.IMAGE_KV.get(`img:${id}`, "json")
  if (!record) return new Response("Not Found", { status: 404 })
  const telegramRes = await fetch(
    `https://api.telegram.org/file/bot${env.BOT_TOKEN}/${record.filePath}`
  )
  res = new Response(telegramRes.body, {
    headers: {
      "Content-Type": telegramRes.headers.get("Content-Type") || "image/jpeg",
      "Cache-Control": "public, max-age=31536000"
    }
  })
  await cache.put(cacheKey, res.clone())
  return res
}
async function compactIndex(env) {
  const meta = await getIndexMeta(env)
  const pageSize = meta.pageSize
  let pageNum = 0
  while (true) {
    const key = `INDEX:page:${pageNum}`
    let page = await env.IMAGE_KV.get(key, "json")
    if (!page) break
    if (!page.length) {
      await env.IMAGE_KV.delete(key)
      pageNum++
      continue
    }
    while (page.length < pageSize) {
      let nextPageNum = pageNum + 1
      let next = null
      while (true) {
        const nextKey = `INDEX:page:${nextPageNum}`
        next = await env.IMAGE_KV.get(nextKey, "json")
        if (!next) break
        if (next.length) break
        await env.IMAGE_KV.delete(nextKey)
        nextPageNum++
      }
      if (!next || !next.length) break
      page.push(next.shift())
      const nextKey = `INDEX:page:${nextPageNum}`
      if (next.length) {
        await env.IMAGE_KV.put(nextKey, JSON.stringify(next))
      } else {
        await env.IMAGE_KV.delete(nextKey)
      }
    }
    await env.IMAGE_KV.put(key, JSON.stringify(page))
    pageNum++
  }
}
async function deleteImages(req, env) {
  const ids = await req.json()
  const cache = caches.default
  const host = req.headers.get("host")
  for (const id of ids) {
    const record = await env.IMAGE_KV.get(`img:${id}`, "json")
    if (!record) continue
    await fetch(
      `https://api.telegram.org/bot${env.BOT_TOKEN}/deleteMessage`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          chat_id: env.GROUP_ID,
          message_id: record.msgId
        })
      }
    )
    await env.IMAGE_KV.delete(`img:${id}`)
    await cache.delete(new Request(`https://${host}/img?id=${id}`))
  }
  await removeFromIndex(env, ids)
  await(compactIndex(env))
  return new Response("ok")
}
function loginPage() {
  return html(`<div class="login-wrap">
<form method="POST" action="/login" class="glass card">
<h2>登录</h2>
<input type="password" name="password" placeholder="请输入密码" required>
<button type="submit">进入</button>
</form>
</div>`, "登录")
}
async function renderPage(req, env, isAdmin) {
  const url = new URL(req.url)
  const page = Math.max(1, Number(url.searchParams.get("page") || 1))
  const PAGE_SIZE = 20
  const meta = await getIndexMeta(env)
  const totalPages = Math.ceil(meta.count / PAGE_SIZE) || 1
  const indexPage = Math.floor((page - 1) * PAGE_SIZE / meta.pageSize)
  const pageData = await env.IMAGE_KV.get(`INDEX:page:${indexPage}`, "json") || []
  const offset = ((page - 1) * PAGE_SIZE) % meta.pageSize
  const ids = pageData.slice(offset, offset + PAGE_SIZE)
  return html(`
<div class="gallery">
${ids.map(id => `<div class="img-box glass card">
${isAdmin ? `<input type="checkbox" data-id="${id}">` : ``}
<img src="/img?id=${id}" loading="lazy">
</div>`).join("")}
</div>
<div class="pager">
${page > 1 ? `<a href="/?page=${page-1}">← 上一页</a>` : ``}
<span>${page} / ${totalPages}</span>
${page < totalPages ? `<a href="/?page=${page+1}">下一页 →</a>` : ``}
</div>
<div class="fab" onclick="toggleMenu()">≡</div>
<div class="side-menu glass card" id="menu">
${isAdmin ? `
<input type="file" id="file2" accept="image/*" multiple>
<button id="uploadBtn" onclick="upload()">上传</button>
<button onclick="del()">删除</button>
` : ``}
<button onclick="location.href='/logout'">退出</button>
</div>
<div class="mask" id="mask" onclick="toggleMenu()"></div>
<script>
const MAX_SIZE = 25 * 1024 * 1024
const menu = document.getElementById("menu")
const mask = document.getElementById("mask")
function toggleMenu(){menu.classList.toggle("open");mask.classList.toggle("show")}
async function upload(){
  const input = document.getElementById("file2")
  const btn = document.getElementById("uploadBtn")
  const files = [...input.files]
  if(!files.length) return
  input.disabled = true
  btn.disabled = true
  let done = 0
  btn.textContent = \`上传中 0/\${files.length}\`
  for(const f of files){
    if(f.size > MAX_SIZE){ done++; continue }
    const fd = new FormData()
    fd.append("file", f)
    await fetch("/", { method:"POST", body:fd })
    done++
    btn.textContent = \`上传中 \${done}/\${files.length}\`
  }
  location.reload()
}
async function del(){
  const ids=[...document.querySelectorAll("input:checked")].map(i=>i.dataset.id)
  if(!ids.length) return
  await fetch("/delete",{method:"POST",body:JSON.stringify(ids)})
  location.reload()
}
</script>
`, "图床")
}
function html(body, title="") {
  return new Response(`<!DOCTYPE html>
<html lang="zh-CN"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
<style>
*{box-sizing:border-box}
h1,h2,h3,h4,h5,h6,p,span,td,th,div,label,button,input,textarea {
  user-select: none;
  background: linear-gradient(270deg, #ff0057, #ffb600, #00ff99, #0066ff, #ff00ff);
  background-size: 1000% 1000%;
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  animation: gradientShift 6s linear infinite, fadeIn 1.5s ease-in forwards;
}
input::placeholder, textarea::placeholder {
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  color: transparent;
}
@keyframes gradientShift {
  0% { background-position: 0% 50%; }
  50% { background-position: 100% 50%; }
  100% { background-position: 0% 50%; }
}
@keyframes fadeIn {
  from { opacity: 0; transform: scale(0.95); }
  to { opacity: 1; transform: scale(1); }
}
body {
  margin:0;
  min-height:100vh;
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto;
  background: linear-gradient(135deg,#e0f7fa,#cce7f0);
  overflow-x: hidden;
}
.glass{
  background: rgba(128,128,128,0.15);
  backdrop-filter: blur(20px) saturate(150%);
  border-radius:20px;
  box-shadow: 0 8px 32px rgba(0,0,0,0.1);
  border: 1px solid rgba(255,255,255,0.2);
}
.card{padding:16px}
.login-wrap{
  display:flex;
  justify-content:center;
  align-items:center;
  height:100vh;
  text-align:center;
  flex-direction: column;
}
.login-wrap form{
  width:360px;
  display:flex;
  flex-direction: column;
  align-items:center;
}
.login-wrap form h2{
  margin-bottom:16px;
  font-size:36px;
}
input,button{
  width:100%;
  padding:14px;
  border-radius:10px;
  border:1px solid #ccc;
  margin-bottom:12px;
  font-size:16px;
  cursor:pointer;
}
button:hover{ transform: scale(1.02); }
button:active{ transform: scale(0.98); }
button:disabled{ opacity:.6; cursor:not-allowed; }
.gallery{display:flex;flex-direction:column;align-items:center;gap:24px;padding:20px}
.img-box{max-width:95%; position:relative;}
.img-box img{max-width:100%;pointer-events:none;}
.img-box input[type="checkbox"]{
  position:absolute;
  top:8px;
  left:8px;
  width:20px;
  height:20px;
  margin:0;
  cursor:pointer;
  accent-color:#007BFF;
  border: 2px solid #ccc;
  border-radius:4px;
  transition: border-color 0.2s, background 0.2s, transform 0.1s;
}
.img-box input[type="checkbox"]:hover{ border-color:#007BFF; }
.img-box input[type="checkbox"]:active{ transform: scale(0.9); }
.img-box input[type="checkbox"]:checked{ background:#007BFF; border-color:#0056b3; }
.fab{
  position:fixed;
  right:20px;
  bottom:20px;
  width:56px;
  height:56px;
  border-radius:50%;
  display:flex;
  align-items:center;
  justify-content:center;
  font-size:28px;
  cursor:pointer;
  z-index:1001;
  transition: background 0.2s, transform 0.1s;
}
.side-menu{
  position:fixed;
  top:0;
  right:-260px;
  width:260px;
  height:100%;
  padding:20px;
  transition:.3s;
  z-index:1002;
}
.side-menu.open{right:0}
.mask{
  position:fixed;
  inset:0;
  background:rgba(0,0,0,.1);
  opacity:0;
  pointer-events:none;
  transition:.3s;
  z-index:1000;
}
input[type="file"]::-webkit-file-upload-button {
  background: linear-gradient(270deg, #ff0057, #ffb600, #00ff99, #0066ff, #ff00ff);
  background-size: 1000% 1000%;
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  font-weight: bold;
  border: 1px solid rgba(255,255,255,0.3);
  border-radius: 6px;
  padding: 6px 12px;
  cursor: pointer;
  animation: gradientShift 6s linear infinite;
}
.mask.show{opacity:1;pointer-events:auto}
</style>
</head><body oncontextmenu="return false">${body}</body></html>`, {
    headers: { "content-type": "text/html; charset=utf-8" }
  })
}
// ===============================
// 会话与权限相关变量
// ===============================
// SESSION_SECRET: 用于 session 的 HMAC 签名，必须保密且随机
// Worker 会用它对用户登录生成的 token 进行签名和验证
// const SESSION_SECRET = "your-random-long-secret"
// ADMIN_PASSWORD: 管理员登录密码
// 如果用户输入这个密码，会被授予 "admin" 角色
// const ADMIN_PASSWORD = "admin123"
// VISITOR_PASSWORD: 访客登录密码
// 如果用户输入这个密码，会被授予 "visitor" 角色
// const VISITOR_PASSWORD = "visitor123"
// ===============================
// Telegram Bot 相关变量
// ===============================
// BOT_TOKEN: Telegram 机器人 token
// 用于上传图片到 Telegram 以及删除消息
// 格式通常是数字:字母和数字组合，例如 "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
// const BOT_TOKEN = "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
// GROUP_ID: Telegram 群组 ID
// 负数表示这是一个群组
// 用于发送图片到指定群组
// const GROUP_ID = "-123456789"
// ===============================
// KV 存储相关变量
// ===============================
// IMAGE_KV: Cloudflare KV 命名空间绑定名
// 用于存储图片索引、图片信息等数据
// 需要在 Worker Dashboard 中绑定 KV 命名空间
// const IMAGE_KV = "image_kv"
// ===============================
