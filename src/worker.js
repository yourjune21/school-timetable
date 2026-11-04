/*
 * 함께 짜는 시간표 — Cloudflare 서버
 *
 * · 화면(index.html)은 public/ 에서 그대로 내보냄 (Workers Static Assets)
 * · /api/s/{학교코드}/... 요청은 학교마다 하나씩 있는 Durable Object(SQLite)가 처리
 * · 인증코드는 서버에서만 확인 (소금+SHA-256 지문으로 저장), 틀리면 잠시 막음
 * · 바뀐 내용은 WebSocket으로 그 학교 화면을 열어 둔 모든 사람에게 바로 보냄
 */
import { DurableObject } from "cloudflare:workers";

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

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (!url.pathname.startsWith("/api/")) return env.ASSETS.fetch(req);
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
    if (url.pathname === "/api/health") return json({ ok: true, app: "tt", v: 1, allowNew: env.ALLOW_NEW_SCHOOL !== "false" });
    const m = url.pathname.match(/^\/api\/s\/([^/]+)(\/.*)$/);
    if (!m || !SID_RE.test(m[1])) return fail(404, "not_found", "잘못된 주소입니다.");
    const sid = m[1];
    const headers = new Headers(req.headers);
    headers.set("x-tt-sid", sid);
    headers.set("x-tt-ip", req.headers.get("cf-connecting-ip") || "local");
    headers.set("x-tt-allow-new", env.ALLOW_NEW_SCHOOL === "false" ? "0" : "1");
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
      CREATE TABLE IF NOT EXISTS fails (k TEXT PRIMARY KEY, n INTEGER NOT NULL, first INTEGER NOT NULL, until INTEGER NOT NULL);`);
  }
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
    if (s.length > 300000) return null;
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

  /* ───── 요청 처리 ───── */
  async fetch(req) {
    const url = new URL(req.url);
    const path = url.pathname, method = req.method;
    try {
      if (path === "/ws") {
        if (req.headers.get("upgrade") !== "websocket") return fail(426, "upgrade", "WebSocket 연결이 필요합니다.");
        const pair = new WebSocketPair();
        this.ctx.acceptWebSocket(pair[1]);
        return new Response(null, { status: 101, webSocket: pair[0] });
      }
      if (path === "/state" && method === "GET") {
        if (!this.exists()) return json({ school: null, slots: {} });
        return json({ school: this.kvGet("school"), slots: this.allSlots() });
      }
      const body = method === "GET" ? {} : await req.json().catch(() => ({}));
      const ip = req.headers.get("x-tt-ip") || "local";

      if (path === "/create" && method === "POST") {
        if (req.headers.get("x-tt-allow-new") !== "1") return fail(403, "closed", "이 서버는 새 학교 만들기를 막아 두었습니다.");
        if (this.exists()) return fail(409, "exists", "이미 있는 학교 코드입니다.");
        const doc = this.cleanSchool(body.doc);
        const code = cleanCode(body.adminCode);
        if (!doc || code.length < 6) return fail(400, "bad", "학교 정보나 관리자 코드(6자 이상)가 올바르지 않습니다.");
        this.setup();
        this.kvSet("school", doc);
        this.kvSet("codes", {});
        const h = await this.setLock(ADMIN, code);
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
        const e = this.cleanEntries(body.e);
        if (!e) return fail(400, "bad", "시간표 자료가 올바르지 않습니다.");
        const at = Date.now();
        this.sql.exec("INSERT INTO slots (pid, e, at) VALUES (?, ?, ?) ON CONFLICT(pid) DO UPDATE SET e=excluded.e, at=excluded.at", pid, JSON.stringify(e), at);
        this.broadcast({ t: "slots", pid, e, at });
        return json({ ok: true });
      }

      // 아래는 관리자만
      if (!admin) return fail(403, "denied", "관리자만 할 수 있습니다.");
      if (path === "/school" && method === "PUT") {
        const doc = this.cleanSchool(body.doc);
        if (!doc) return fail(400, "bad", "학교 설정 자료가 올바르지 않습니다.");
        this.kvSet("school", doc);
        this.broadcast({ t: "school", school: doc });
        return json({ ok: true });
      }
      if (path === "/code" && method === "POST") {
        const pid = String(body.pid || "");
        const code = cleanCode(body.code);
        if (!(pid === ADMIN || (PID_RE.test(pid) && people.has(pid)))) return fail(400, "bad", "없는 선생님입니다.");
        if (code.length < (pid === ADMIN ? 6 : 4)) return fail(400, "bad", pid === ADMIN ? "관리자 코드는 6자 이상입니다." : "코드가 너무 짧습니다.");
        const h = await this.setLock(pid, code);
        if (pid === ADMIN) return json({ ok: true, token: this.newSession(ADMIN, h) });
        const codes = this.kvGet("codes") || {};
        codes[pid] = code;
        this.kvSet("codes", codes);
        return json({ ok: true });
      }
      if (path === "/codes" && method === "GET") return json({ codes: this.kvGet("codes") || {} });
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
