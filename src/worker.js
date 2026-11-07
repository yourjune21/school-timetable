/*
 * 함께 짜는 시간표 — Cloudflare 서버
 *
 * · 화면(index.html)은 public/ 에서 그대로 내보냄 (Workers Static Assets)
 * · /api/s/{학교코드}/... 요청은 학교마다 하나씩 있는 Durable Object(SQLite)가 처리
 * · 인증코드는 서버에서만 확인 (소금+SHA-256 지문으로 저장), 틀리면 잠시 막음
 * · 바뀐 내용은 WebSocket으로 그 학교 화면을 열어 둔 모든 사람에게 바로 보냄
 */
import { DurableObject } from "cloudflare:workers";
import { VERSION } from "./version.js";

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-headers": "content-type,x-tt-tokens",
  "access-control-allow-methods": "GET,POST,PUT,OPTIONS",
};
const json = (o, status = 200) =>
  new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...CORS } });
const fail = (status, error, message, extra = {}) => json({ error, message, ...extra }, status);

const SID_RE = /^[a-z0-9][a-z0-9-]{2,29}$/;
const PID_RE = /^[A-Za-z0-9_-]{1,40}$/;
const KEY_RE = /^\d{1,2}-\d{1,2}\|[1-6]\|[1-9]$/;
const ADMIN = "_admin";
const REGISTRY = "_registry";
const norm = (v) => String(v || "").toLowerCase().replace(/[\s·.\-_()]/g, "");

function diffEntries(a, b) {
  a = a || {}; b = b || {}; const out = { add: 0, del: 0, chg: 0, keys: [] };
  new Set([...Object.keys(a), ...Object.keys(b)]).forEach((k) => {
    const x = a[k], y = b[k];
    if (!x && y) { out.add++; out.keys.push(["+", k, y.s || ""]); }
    else if (x && !y) { out.del++; out.keys.push(["-", k, x.s || ""]); }
    else if (x && y && (x.s !== y.s || (x.r || "") !== (y.r || "") || !!x.j !== !!y.j)) { out.chg++; out.keys.push(["~", k, y.s || ""]); }
  });
  out.keys = out.keys.slice(0, 40);
  return out;
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (!url.pathname.startsWith("/api/")) return env.ASSETS.fetch(req);
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
    if (url.pathname === "/api/health") return json({ ok: true, app: "tt", v: 1, version: VERSION, allowNew: env.ALLOW_NEW_SCHOOL !== "false", superOnly: true, search: true });
    if (url.pathname === "/api/search") {
      // 첫 화면 학교 검색: 학교 목록은 '_registry' 라는 이름의 저장소 하나에 모아 둠 (학교 코드 규칙과 겹치지 않는 이름)
      const q = String(url.searchParams.get("q") || "").slice(0, 40);
      return env.SCHOOL.get(env.SCHOOL.idFromName(REGISTRY)).fetch(new Request(`https://school.internal/reg/search?q=${encodeURIComponent(q)}`, { headers: { "x-tt-sid": REGISTRY } }));
    }
    // 최고관리자 창: 모든 학교 보기 · 학교관리자 코드 다시 정하기
    if (url.pathname.startsWith("/api/super/") && req.method === "POST") {
      const b = await req.json().catch(() => ({}));
      const reg = env.SCHOOL.get(env.SCHOOL.idFromName(REGISTRY));
      const ip = req.headers.get("cf-connecting-ip") || "local";
      const chk = await reg.fetch(new Request("https://school.internal/reg/super", { method: "POST", headers: { "x-tt-sid": REGISTRY, "content-type": "application/json", "x-tt-ip": ip, "x-tt-super-code": String(env.SUPER_CODE || "") }, body: JSON.stringify({ code: b.code || "" }) }));
      if (!chk.ok) return chk;
      if (url.pathname === "/api/super/schools") {
        // 학교 목록 + 각 학교의 학교관리자 코드 (최고관리자에게만)
        const r = await reg.fetch(new Request("https://school.internal/reg/all", { headers: { "x-tt-sid": REGISTRY } }));
        const j = await r.json().catch(() => ({ schools: [] }));
        const schools = await Promise.all((j.schools || []).map(async (x) => {
          if (!SID_RE.test(String(x.sid || ""))) return x;
          try { const q = await env.SCHOOL.get(env.SCHOOL.idFromName(x.sid)).fetch(new Request("https://school.internal/super-info", { method: "POST", headers: { "x-tt-sid": x.sid, "x-tt-super-ok": "1", "content-type": "application/json" }, body: "{}" })); const k = await q.json(); return { ...x, adminCode: k.admin || "" }; } catch (e) { return x; }
        }));
        return json({ schools });
      }
      if (url.pathname === "/api/super/admin-code") {
        const sid = String(b.sid || "");
        if (!SID_RE.test(sid)) return fail(400, "bad", "학교 코드가 올바르지 않습니다.");
        return env.SCHOOL.get(env.SCHOOL.idFromName(sid)).fetch(new Request("https://school.internal/super-admin-code", { method: "POST", headers: { "x-tt-sid": sid, "x-tt-super-ok": "1", "content-type": "application/json" }, body: JSON.stringify({ code: b.newCode || "" }) }));
      }
      if (url.pathname === "/api/super/check") return json({ ok: true });
      if (url.pathname === "/api/super/enter") {
        // 최고관리자가 학교관리자 코드 없이 그 학교 기본설정에 들어감 (관리자 세션 발급)
        const sid = String(b.sid || "");
        if (!SID_RE.test(sid)) return fail(400, "bad", "학교 코드가 올바르지 않습니다.");
        return env.SCHOOL.get(env.SCHOOL.idFromName(sid)).fetch(new Request("https://school.internal/super-session", { method: "POST", headers: { "x-tt-sid": sid, "x-tt-super-ok": "1", "content-type": "application/json" }, body: "{}" }));
      }
      return fail(404, "not_found", "잘못된 주소입니다.");
    }
    const m = url.pathname.match(/^\/api\/s\/([^/]+)(\/.*)$/);
    if (!m || !SID_RE.test(m[1])) return fail(404, "not_found", "잘못된 주소입니다.");
    const sid = m[1];
    const headers = new Headers(req.headers);
    headers.set("x-tt-sid", sid);
    headers.set("x-tt-ip", req.headers.get("cf-connecting-ip") || "local");
    headers.set("x-tt-allow-new", env.ALLOW_NEW_SCHOOL === "false" ? "0" : "1");
    headers.delete("x-tt-super-ok"); // 밖에서 보낸 값은 버림
    // 새 학교 만들기: 최고관리자 코드(SUPER_CODE 비밀값)를 한 곳(_registry)에서 확인 — 틀린 횟수도 거기서 셈
    if (m[2] === "/create" && req.method === "POST") {
      let b = {};
      try { b = await req.clone().json(); } catch (e) {}
      const r = await env.SCHOOL.get(env.SCHOOL.idFromName(REGISTRY)).fetch(new Request("https://school.internal/reg/super", {
        method: "POST",
        headers: { "x-tt-sid": REGISTRY, "content-type": "application/json", "x-tt-ip": headers.get("x-tt-ip"), "x-tt-super-code": String(env.SUPER_CODE || "") },
        body: JSON.stringify({ code: b.superCode || "" }),
      }));
      if (!r.ok) return r;
      headers.set("x-tt-super-ok", "1");
    }
    const inner = new Request(new URL(m[2] + url.search, "https://school.internal"), { method: req.method, headers, body: req.body });
    return env.SCHOOL.get(env.SCHOOL.idFromName(sid)).fetch(inner);
  },
};

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const sha = async (s) => hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));
const rand = (n) => hex(crypto.getRandomValues(new Uint8Array(n)));
const cleanCode = (v) => String(v || "").toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 24);

export class SchoolDO extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
  }

  /* ───── 저장소 ───── */
  exists() {
    return this.sql.exec("SELECT count(*) AS n FROM sqlite_master WHERE type='table' AND name='kv'").one().n > 0
      && this.sql.exec("SELECT count(*) AS n FROM kv WHERE k='school'").one().n > 0;
  }
  setup() {
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS locks (pid TEXT PRIMARY KEY, salt TEXT NOT NULL, h TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS slots (pid TEXT PRIMARY KEY, e TEXT NOT NULL, at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, pid TEXT NOT NULL, lh TEXT NOT NULL, at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS fails (k TEXT PRIMARY KEY, n INTEGER NOT NULL, first INTEGER NOT NULL, until INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS changes (id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, pid TEXT NOT NULL, by TEXT NOT NULL, d TEXT NOT NULL);`);
  }
  ensureChanges() { this.sql.exec("CREATE TABLE IF NOT EXISTS changes (id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, pid TEXT NOT NULL, by TEXT NOT NULL, d TEXT NOT NULL)"); }
  kvGet(k) { const r = this.sql.exec("SELECT v FROM kv WHERE k=?", k).toArray()[0]; return r ? JSON.parse(r.v) : null; }
  kvSet(k, v) { this.sql.exec("INSERT INTO kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", k, JSON.stringify(v)); }
  allSlots() {
    const out = {};
    for (const r of this.sql.exec("SELECT pid, e, at FROM slots")) out[r.pid] = { e: JSON.parse(r.e), at: r.at };
    return out;
  }
  async setLock(pid, code) {
    const salt = rand(16);
    const h = await sha(`${salt}|${cleanCode(code)}`);
    this.sql.exec("INSERT INTO locks (pid, salt, h) VALUES (?, ?, ?) ON CONFLICT(pid) DO UPDATE SET salt=excluded.salt, h=excluded.h", pid, salt, h);
    this.sql.exec("DELETE FROM sessions WHERE pid=?", pid); // 예전 코드로 들어온 기기는 모두 끊김
    return h;
  }
  newSession(pid, lh) {
    const token = rand(24);
    this.sql.exec("INSERT INTO sessions (token, pid, lh, at) VALUES (?, ?, ?, ?)", token, pid, lh, Date.now());
    return token;
  }
  granted(req) {
    const toks = String(req.headers.get("x-tt-tokens") || "").split(/[\s,]+/).filter((t) => /^[0-9a-f]{48}$/.test(t)).slice(0, 6);
    const pids = new Set();
    for (const t of toks) {
      const r = this.sql.exec("SELECT s.pid FROM sessions s JOIN locks l ON l.pid = s.pid AND l.h = s.lh WHERE s.token=?", t).toArray()[0];
      if (r) pids.add(r.pid);
    }
    return pids;
  }
  broadcast(msg) {
    const s = JSON.stringify(msg);
    for (const ws of this.ctx.getWebSockets()) { try { ws.send(s); } catch (e) {} }
  }

  /* ───── 시도 제한: 한 사람 15분에 8번, 한 곳(IP) 1시간에 100번 ───── */
  blocked(keys) {
    const now = Date.now();
    for (const k of keys) {
      const r = this.sql.exec("SELECT until FROM fails WHERE k=?", k).toArray()[0];
      if (r && r.until > now) return Math.ceil((r.until - now) / 1000);
    }
    return 0;
  }
  addFail(k, max, windowMs) {
    const now = Date.now();
    const r = this.sql.exec("SELECT n, first FROM fails WHERE k=?", k).toArray()[0];
    let n = 1, first = now;
    if (r && now - r.first < windowMs) { n = r.n + 1; first = r.first; }
    const until = n >= max ? now + windowMs : 0;
    this.sql.exec("INSERT INTO fails (k, n, first, until) VALUES (?, ?, ?, ?) ON CONFLICT(k) DO UPDATE SET n=excluded.n, first=excluded.first, until=excluded.until", k, n, first, until);
  }

  /* ───── 받은 자료 다듬기 ───── */
  cleanSchool(doc) {
    if (!doc || typeof doc !== "object" || Array.isArray(doc)) return null;
    const s = JSON.stringify(doc);
    if (s.length > 900000) return null; // 보관함(지난 학기 3개)까지 담아도 넉넉하게 (WebSocket 1MB 아래)
    if (!Array.isArray(doc.people) || !Array.isArray(doc.subjects) || !Array.isArray(doc.classCounts)) return null;
    if (doc.people.some((p) => !p || !PID_RE.test(p.id || "") || p.id === ADMIN)) return null;
    return JSON.parse(s);
  }
  cleanEntries(e) {
    if (!e || typeof e !== "object" || Array.isArray(e)) return null;
    const keys = Object.keys(e);
    if (keys.length > 1500) return null;
    const out = {};
    for (const k of keys) {
      const v = e[k];
      if (!KEY_RE.test(k) || !v || typeof v !== "object") return null;
      out[k] = { s: String(v.s || "").slice(0, 40), r: String(v.r || "").slice(0, 40) };
      if (v.j) out[k].j = 1; // 협력수업(함께 들어가기)
    }
    return out;
  }

  /* ───── 학교 목록(검색용) ───── */
  async register(sid) {
    if (!sid || !SID_RE.test(sid) || !this.exists()) return;
    const sc = this.kvGet("school") || {};
    const row = { sid, name: String(sc.name || "").slice(0, 60), listed: sc.listed !== false };
    const mark = JSON.stringify(row);
    if (this.kvGet("reg") === mark) return;
    try {
      const r = await this.env.SCHOOL.get(this.env.SCHOOL.idFromName(REGISTRY)).fetch(new Request("https://school.internal/reg/put", { method: "POST", headers: { "x-tt-sid": REGISTRY, "content-type": "application/json" }, body: mark }));
      if (r.ok) this.kvSet("reg", mark);
    } catch (e) {}
  }
  regTable() { this.sql.exec("CREATE TABLE IF NOT EXISTS reg (sid TEXT PRIMARY KEY, name TEXT NOT NULL, key TEXT NOT NULL, listed INTEGER NOT NULL, at INTEGER NOT NULL)"); }
  async regFetch(req, path) {
    this.regTable();
    if (path === "/reg/super" && req.method === "POST") {
      this.sql.exec("CREATE TABLE IF NOT EXISTS fails (k TEXT PRIMARY KEY, n INTEGER NOT NULL, first INTEGER NOT NULL, until INTEGER NOT NULL)");
      const want = cleanCode(req.headers.get("x-tt-super-code") || "");
      if (want.length < 8) return fail(403, "no_super", "서버에 최고관리자 코드(SUPER_CODE, 영문·숫자 8자 이상)가 설정되어 있지 않아 새 학교를 만들 수 없습니다.");
      const ip = req.headers.get("x-tt-ip") || "local";
      const wait = this.blocked([`super:${ip}`, "super:all"]);
      if (wait) return fail(429, "wait", `최고관리자 코드를 여러 번 틀려 잠시 막았습니다. ${Math.ceil(wait / 60)}분 뒤에 다시 해 주세요.`, { wait });
      const b = await req.json().catch(() => ({}));
      const [x, y] = await Promise.all([sha("super|" + cleanCode(b.code)), sha("super|" + want)]);
      if (x !== y) {
        this.addFail(`super:${ip}`, 5, 30 * 60 * 1000);
        this.addFail("super:all", 30, 60 * 60 * 1000);
        return fail(403, "super", "최고관리자 코드가 맞지 않습니다.");
      }
      this.sql.exec("DELETE FROM fails WHERE k=?", `super:${ip}`);
      return json({ ok: true });
    }
    if (path === "/reg/put" && req.method === "POST") {
      const b = await req.json().catch(() => ({}));
      if (!SID_RE.test(b.sid || "")) return fail(400, "bad", "잘못된 요청입니다.");
      this.sql.exec("INSERT INTO reg (sid, name, key, listed, at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(sid) DO UPDATE SET name=excluded.name, key=excluded.key, listed=excluded.listed, at=excluded.at",
        b.sid, String(b.name || ""), norm(b.name) + " " + b.sid, b.listed ? 1 : 0, Date.now());
      return json({ ok: true });
    }
    if (path === "/reg/all") {
      const rows = this.sql.exec("SELECT sid, name, listed, at FROM reg ORDER BY name").toArray();
      return json({ schools: rows });
    }
    if (path === "/reg/search") {
      const q = norm(new URL(req.url).searchParams.get("q"));
      if (!q) return json({ results: [] });
      const like = "%" + q.replace(/[%_]/g, "") + "%";
      const rows = this.sql.exec("SELECT sid, name FROM reg WHERE listed = 1 AND key LIKE ? ORDER BY (CASE WHEN sid = ? THEN 0 WHEN key LIKE ? THEN 1 ELSE 2 END), name LIMIT 10", like, q, q + "%").toArray();
      return json({ results: rows });
    }
    return fail(404, "not_found", "잘못된 주소입니다.");
  }

  /* ───── 요청 처리 ───── */
  async fetch(req) {
    const url = new URL(req.url);
    const path = url.pathname, method = req.method;
    const sidH = req.headers.get("x-tt-sid") || "";
    if (sidH === REGISTRY) return this.regFetch(req, path);
    try {
      if (path === "/ws") {
        if (req.headers.get("upgrade") !== "websocket") return fail(426, "upgrade", "WebSocket 연결이 필요합니다.");
        const pair = new WebSocketPair();
        this.ctx.acceptWebSocket(pair[1]);
        return new Response(null, { status: 101, webSocket: pair[0] });
      }
      if (path === "/state" && method === "GET") {
        if (!this.exists()) return json({ school: null, slots: {} });
        this.ctx.waitUntil(this.register(sidH)); // 예전에 만든 학교도 처음 열릴 때 검색 목록에 올라감
        return json({ school: this.kvGet("school"), slots: this.allSlots(), book: this.kvGet("book") || {} });
      }
      const body = method === "GET" ? {} : await req.json().catch(() => ({}));
      const ip = req.headers.get("x-tt-ip") || "local";

      if (path === "/super-session" && method === "POST") {
        if (req.headers.get("x-tt-super-ok") !== "1") return fail(403, "super", "최고관리자만 할 수 있습니다.");
        if (!this.exists()) return fail(404, "not_found", "없는 학교입니다.");
        const lock = this.sql.exec("SELECT h FROM locks WHERE pid=?", ADMIN).toArray()[0];
        if (!lock) return fail(400, "bad", "학교관리자 코드가 없습니다. 먼저 코드를 정하세요.");
        return json({ ok: true, token: this.newSession(ADMIN, lock.h) });
      }
      if (path === "/super-info" && method === "POST") {
        if (req.headers.get("x-tt-super-ok") !== "1") return fail(403, "super", "최고관리자만 할 수 있습니다.");
        return json({ admin: this.exists() ? this.kvGet("admincode") || "" : "" });
      }
      if (path === "/super-admin-code" && method === "POST") {
        if (req.headers.get("x-tt-super-ok") !== "1") return fail(403, "super", "최고관리자만 할 수 있습니다.");
        if (!this.exists()) return fail(404, "not_found", "없는 학교입니다.");
        const code = cleanCode(body.code);
        if (code.length < 6) return fail(400, "bad", "학교관리자 코드는 영문·숫자 6자 이상입니다.");
        await this.setLock(ADMIN, code);
        this.kvSet("admincode", code);
        return json({ ok: true });
      }
      if (path === "/create" && method === "POST") {
        if (req.headers.get("x-tt-allow-new") !== "1") return fail(403, "closed", "이 서버는 새 학교 만들기를 막아 두었습니다.");
        if (req.headers.get("x-tt-super-ok") !== "1") return fail(403, "super", "새 학교는 최고관리자만 만들 수 있습니다.");
        if (this.exists()) return fail(409, "exists", "이미 있는 학교 코드입니다.");
        const doc = this.cleanSchool(body.doc);
        const code = cleanCode(body.adminCode);
        if (!doc || code.length < 6) return fail(400, "bad", "학교 정보나 관리자 코드(6자 이상)가 올바르지 않습니다.");
        this.setup();
        this.kvSet("school", doc);
        this.kvSet("codes", {});
        const h = await this.setLock(ADMIN, code);
        this.kvSet("admincode", code);
        await this.register(sidH);
        return json({ token: this.newSession(ADMIN, h) });
      }

      if (!this.exists()) return fail(404, "no_school", "학교를 찾지 못했습니다.");

      if (path === "/login" && method === "POST") {
        const pid = String(body.pid || "");
        if (!PID_RE.test(pid)) return fail(400, "bad", "잘못된 요청입니다.");
        const keys = [`p:${pid}`, `ip:${ip}`];
        const wait = this.blocked(keys);
        if (wait) return fail(429, "wait", `인증코드를 여러 번 틀려 잠시 막았습니다. ${Math.ceil(wait / 60)}분 뒤에 다시 해 주세요.`, { wait });
        const lock = this.sql.exec("SELECT salt, h FROM locks WHERE pid=?", pid).toArray()[0];
        const h = lock ? await sha(`${lock.salt}|${cleanCode(body.code)}`) : "";
        if (!lock || h !== lock.h) {
          this.addFail(`p:${pid}`, 8, 15 * 60 * 1000);
          this.addFail(`ip:${ip}`, 100, 60 * 60 * 1000); // 학교는 여러 선생님이 같은 IP를 씀
          return json({ ok: false });
        }
        this.sql.exec("DELETE FROM fails WHERE k=?", `p:${pid}`);
        this.sql.exec("DELETE FROM sessions WHERE at < ?", Date.now() - 400 * 86400000);
        return json({ ok: true, token: this.newSession(pid, lock.h) });
      }
      if (path === "/logout" && method === "POST") {
        this.sql.exec("DELETE FROM sessions WHERE token=?", String(body.token || ""));
        return json({ ok: true });
      }
      const me = this.granted(req);
      const admin = me.has(ADMIN);
      if (path === "/check" && method === "GET") return json({ pids: [...me] });

      const school = this.kvGet("school");
      const people = new Set((school.people || []).map((p) => p.id));

      const slotMatch = path.match(/^\/slots\/([A-Za-z0-9_-]{1,40})$/);
      if (slotMatch && method === "PUT") {
        const pid = slotMatch[1];
        if (!admin && !me.has(pid)) return fail(403, "denied", "권한이 없습니다. 인증코드로 다시 들어와 주세요.");
        if (!people.has(pid)) return fail(400, "bad", "없는 선생님입니다.");
        if (!admin && (this.kvGet("school") || {}).finalized) return fail(403, "finalized", "시간표가 확정(3단계)되어 고칠 수 없습니다.");
        const e = this.cleanEntries(body.e);
        if (!e) return fail(400, "bad", "시간표 자료가 올바르지 않습니다.");
        const at = Date.now();
        // 변경 기록: 누가(본인/관리자) 몇 칸을 더하고·빼고·바꿨는지 (최근 500건)
        try {
          this.ensureChanges();
          const old = [...this.sql.exec("SELECT e FROM slots WHERE pid=?", pid)][0];
          const df = diffEntries(old ? JSON.parse(old.e) : {}, e);
          if (df.add + df.del + df.chg) {
            this.sql.exec("INSERT INTO changes (at, pid, by, d) VALUES (?, ?, ?, ?)", at, pid, me.has(pid) ? pid : ADMIN, JSON.stringify(df));
            this.sql.exec("DELETE FROM changes WHERE id <= (SELECT MAX(id) - 500 FROM changes)");
          }
        } catch (err) {}
        this.sql.exec("INSERT INTO slots (pid, e, at) VALUES (?, ?, ?) ON CONFLICT(pid) DO UPDATE SET e=excluded.e, at=excluded.at", pid, JSON.stringify(e), at);
        this.broadcast({ t: "slots", pid, e, at });
        return json({ ok: true });
      }
      // 지우고 넣기: 다른 사람이 넣은 칸 몇 개를 지움
      // 관리자는 누구 것이든, 교과전담·강사는 담임이 넣은 칸만 (담임은 교과전담 칸을 지울 수 없음)
      if (path === "/take" && method === "POST") {
        const pid = String(body.pid || ""), from = String(body.from || "");
        const keys = Array.isArray(body.keys) ? body.keys.map(String).slice(0, 12) : [];
        const P = (id) => (school.people || []).find((x) => x.id === id);
        if (!people.has(pid) || !people.has(from) || pid === from || !keys.length) return fail(400, "bad", "요청이 올바르지 않습니다.");
        if (!admin && !me.has(pid)) return fail(403, "denied", "권한이 없습니다. 인증코드로 다시 들어와 주세요.");
        if (!admin && school.finalized) return fail(403, "finalized", "시간표가 확정(3단계)되어 고칠 수 없습니다.");
        if (!admin && !(P(pid).role !== "homeroom" && P(from).role === "homeroom")) return fail(403, "denied", "다른 선생님 수업은 그 선생님이나 관리자만 지울 수 있습니다.");
        const row = [...this.sql.exec("SELECT e FROM slots WHERE pid=?", from)][0];
        const old = row ? JSON.parse(row.e) : {}, e = { ...old };
        keys.forEach((k) => { if (e[k] && !e[k].b) delete e[k]; });
        const at = Date.now();
        try {
          this.ensureChanges(); const df = diffEntries(old, e);
          if (df.del) this.sql.exec("INSERT INTO changes (at, pid, by, d) VALUES (?, ?, ?, ?)", at, from, me.has(pid) ? pid : ADMIN, JSON.stringify(df));
        } catch (err) {}
        this.sql.exec("INSERT INTO slots (pid, e, at) VALUES (?, ?, ?) ON CONFLICT(pid) DO UPDATE SET e=excluded.e, at=excluded.at", from, JSON.stringify(e), at);
        this.broadcast({ t: "slots", pid: from, e, at });
        return json({ ok: true, e });
      }
      if (path === "/changes" && method === "GET") {
        if (!admin) return fail(403, "denied", "관리자만 볼 수 있습니다.");
        this.ensureChanges();
        const out = [...this.sql.exec("SELECT at, pid, by, d FROM changes ORDER BY id DESC LIMIT 200")].map((r) => ({ at: r.at, pid: r.pid, by: r.by, ...JSON.parse(r.d) }));
        return json({ changes: out });
      }

      // 특별실 예약 시간표 (학급 시간표와 따로): 들어온 선생님 누구나 빈 칸에 넣고, 자기가 넣은 칸만 고침 (관리자는 모두)
      if (path === "/book" && method === "PUT") {
        if (!me.size) return fail(403, "denied", "인증코드로 들어와야 넣을 수 있습니다.");
        const room = String(body.room || "").slice(0, 40), k = String(body.k || "");
        const book = this.kvGet("book") || {};
        if (body.clear) {
          if (!admin) return fail(403, "denied", "관리자만 특별실 시간표를 모두 지울 수 있습니다.");
          delete book[room];
        } else {
          if (!room || !/^[0-9]\|[0-9]{1,2}(\|[0-9]{3,4})?(~[2-9])?$/.test(k)) return fail(400, "bad", "잘못된 칸입니다.");
          const cur = (book[room] || {})[k];
          if (cur && !admin && !me.has(cur.by)) return fail(403, "taken", "다른 선생님이 넣은 칸입니다. 그 선생님이나 관리자만 바꿀 수 있습니다.");
          if (!body.v) { if (book[room]) delete book[room][k]; }
          else {
            const by = me.has(String(body.v.by || "")) ? String(body.v.by) : [...me].find((x) => x !== ADMIN) || ADMIN;
            (book[room] = book[room] || {})[k] = { t: String(body.v.t || "").slice(0, 40), cls: String(body.v.cls || "").slice(0, 12), by, at: Date.now() };
          }
        }
        if (JSON.stringify(book).length > 300000) return fail(413, "too_big", "특별실 시간표가 너무 큽니다.");
        this.kvSet("book", book);
        this.broadcast({ t: "book", book });
        return json({ ok: true });
      }
      // 선생님이 자기 기본 교실을 정함 (학교 설정 중 자기 줄의 room 하나만)
      if (path === "/me-room" && method === "POST") {
        const pid = String(body.pid || ""), room = String(body.room || "");
        if (!admin && !me.has(pid)) return fail(403, "denied", "권한이 없습니다. 인증코드로 다시 들어와 주세요.");
        const p = (school.people || []).find((x) => x.id === pid);
        if (!p) return fail(400, "bad", "없는 선생님입니다.");
        if (room && !(school.rooms || []).some((r) => r.id === room)) return fail(400, "bad", "없는 장소입니다.");
        p.room = room;
        this.kvSet("school", school);
        this.broadcast({ t: "school", school });
        return json({ ok: true });
      }

      // 아래는 관리자만
      if (!admin) return fail(403, "denied", "관리자만 할 수 있습니다.");
      if (path === "/school" && method === "PUT") {
        const doc = this.cleanSchool(body.doc);
        if (!doc) return fail(400, "bad", "학교 설정 자료가 올바르지 않습니다.");
        this.kvSet("school", doc);
        this.broadcast({ t: "school", school: doc });
        await this.register(sidH);
        return json({ ok: true });
      }
      if (path === "/code" && method === "POST") {
        const pid = String(body.pid || "");
        const code = cleanCode(body.code);
        if (!(pid === ADMIN || (PID_RE.test(pid) && people.has(pid)))) return fail(400, "bad", "없는 선생님입니다.");
        if (code.length < (pid === ADMIN ? 6 : 4)) return fail(400, "bad", pid === ADMIN ? "관리자 코드는 6자 이상입니다." : "코드가 너무 짧습니다.");
        const h = await this.setLock(pid, code);
        if (pid === ADMIN) { this.kvSet("admincode", code); return json({ ok: true, token: this.newSession(ADMIN, h) }); }
        const codes = this.kvGet("codes") || {};
        codes[pid] = code;
        this.kvSet("codes", codes);
        return json({ ok: true });
      }
      if (path === "/codes" && method === "GET") return json({ codes: this.kvGet("codes") || {}, admin: this.kvGet("admincode") || "" });
      if (path === "/remove" && method === "POST") {
        const pid = String(body.pid || "");
        if (!PID_RE.test(pid) || pid === ADMIN) return fail(400, "bad", "잘못된 요청입니다.");
        this.sql.exec("DELETE FROM locks WHERE pid=?", pid);
        this.sql.exec("DELETE FROM sessions WHERE pid=?", pid);
        this.sql.exec("DELETE FROM slots WHERE pid=?", pid);
        const codes = this.kvGet("codes") || {};
        delete codes[pid];
        this.kvSet("codes", codes);
        this.broadcast({ t: "slots", pid, e: null });
        return json({ ok: true });
      }
      if (path === "/clear" && method === "POST") {
        if (Array.isArray(body.pids)) for (const p of body.pids) this.sql.exec("DELETE FROM slots WHERE pid=?", String(p));
        else this.sql.exec("DELETE FROM slots");
        this.broadcast({ t: "all", slots: this.allSlots() });
        return json({ ok: true });
      }
      if (path === "/all-slots" && method === "PUT") {
        const slots = body.slots && typeof body.slots === "object" ? body.slots : null;
        if (!slots) return fail(400, "bad", "자료가 올바르지 않습니다.");
        const clean = {};
        for (const [pid, d] of Object.entries(slots)) {
          const e = this.cleanEntries(d && d.e);
          if (!PID_RE.test(pid) || !e) return fail(400, "bad", "시간표 자료가 올바르지 않습니다.");
          clean[pid] = e;
        }
        this.sql.exec("DELETE FROM slots");
        const at = Date.now();
        for (const [pid, e] of Object.entries(clean)) this.sql.exec("INSERT INTO slots (pid, e, at) VALUES (?, ?, ?)", pid, JSON.stringify(e), at);
        this.broadcast({ t: "all", slots: this.allSlots() });
        return json({ ok: true });
      }
      return fail(404, "not_found", "잘못된 주소입니다.");
    } catch (e) {
      return fail(500, "server", "서버 오류: " + (e && e.message ? e.message : String(e)));
    }
  }

  webSocketMessage(ws, msg) { if (msg === "ping") ws.send("pong"); }
  webSocketClose(ws, code) { try { ws.close(code === 1005 ? 1000 : code, "bye"); } catch (e) {} }
  webSocketError() {}
}
