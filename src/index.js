// Fluxo de Caixa — API (Cloudflare Worker + D1)
// Rotas em /api/*; o resto é servido de ./public pelos assets.

const SESSION_DAYS = 30;
const INVITE_DAYS = 7;
const PBKDF2_ITER = 100000;
const MAX_DATA = 900 * 1024;
const COLS = ['lanc', 'inv', 'metas'];
const CODE_ALPH = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // 32 símbolos, sem 0/O/1/I

const enc = new TextEncoder();
const now = () => Date.now();

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers },
  });
}
const err = (status, message) => json({ error: message }, status);

const toHex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
const fromHex = (h) => new Uint8Array(h.match(/../g).map((x) => parseInt(x, 16)));
const randHex = (n) => toHex(crypto.getRandomValues(new Uint8Array(n)));
const inviteCode = () => [...crypto.getRandomValues(new Uint8Array(8))].map((b) => CODE_ALPH[b % 32]).join('');

async function hashPassword(password, saltHex) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: fromHex(saltHex), iterations: PBKDF2_ITER },
    key,
    256,
  );
  return toHex(bits);
}
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

function getCookie(req, name) {
  const c = req.headers.get('cookie') || '';
  for (const part of c.split(/;\s*/)) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i) === name) return decodeURIComponent(part.slice(i + 1));
  }
  return null;
}
function sessionCookie(token, maxAge) {
  return `fc_sess=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

async function readJson(req) {
  try {
    return await req.json();
  } catch {
    return {};
  }
}

async function currentUser(req, env) {
  const token = getCookie(req, 'fc_sess');
  if (!token) return null;
  const row = await env.DB.prepare(
    'SELECT u.id, u.username, u.name, s.expires_at FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?',
  ).bind(token).first();
  if (!row) return null;
  if (row.expires_at < now()) {
    await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
    return null;
  }
  return { id: row.id, username: row.username, name: row.name, token };
}

async function startSession(env, userId) {
  const token = randHex(32);
  await env.DB.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)')
    .bind(token, userId, now() + SESSION_DAYS * 864e5).run();
  return token;
}

const emptyData = () => ({ anos: 20, lanc: [], inv: [], metas: [] });

async function createRoom(env, userId, name) {
  const id = randHex(10);
  const t = now();
  await env.DB.batch([
    env.DB.prepare('INSERT INTO rooms (id, name, owner_id, data, version, updated_at, updated_by) VALUES (?, ?, ?, ?, 1, ?, ?)')
      .bind(id, name, userId, JSON.stringify(emptyData()), t, userId),
    env.DB.prepare('INSERT INTO members (room_id, user_id, role, joined_at) VALUES (?, ?, ?, ?)').bind(id, userId, 'dono', t),
  ]);
  return id;
}

async function membership(env, roomId, userId) {
  return env.DB.prepare('SELECT role FROM members WHERE room_id = ? AND user_id = ?').bind(roomId, userId).first();
}

async function roomMembers(env, roomId) {
  const { results } = await env.DB.prepare(
    'SELECT u.id, u.name, u.username, m.role FROM members m JOIN users u ON u.id = m.user_id WHERE m.room_id = ? ORDER BY m.joined_at',
  ).bind(roomId).all();
  return results;
}

// ---------- dados da sala ----------
function cleanItem(item, uid, prev) {
  if (!item || typeof item !== 'object' || Array.isArray(item)) return null;
  if (typeof item.id !== 'string' || !/^[A-Za-z0-9_-]{1,40}$/.test(item.id)) return null;
  if (JSON.stringify(item).length > 4000) return null;
  const out = { ...item };
  out.by = prev?.by || uid;
  return out;
}

function applyOps(data, ops, uid) {
  for (const o of ops) {
    if (!o || typeof o !== 'object') continue;
    if (o.op === 'set' && o.key === 'anos') {
      const v = Math.floor(+o.value);
      if (v >= 1 && v <= 100000) data.anos = v;
    } else if (o.op === 'put' && COLS.includes(o.col)) {
      const arr = data[o.col];
      const i = arr.findIndex((x) => x.id === o.item?.id);
      const it = cleanItem(o.item, uid, i >= 0 ? arr[i] : null);
      if (!it) continue;
      if (i >= 0) arr[i] = it;
      else arr.push(it);
    } else if (o.op === 'del' && COLS.includes(o.col)) {
      data[o.col] = data[o.col].filter((x) => x.id !== o.id);
    }
  }
  return data;
}

async function getRoom(env, roomId) {
  return env.DB.prepare('SELECT id, name, owner_id, data, version, updated_at FROM rooms WHERE id = ?').bind(roomId).first();
}

// ---------- rotas ----------
async function handleApi(req, env, url) {
  const path = url.pathname.replace(/\/+$/, '');
  const method = req.method;

  // Proteção simples contra requisições de outros sites
  if (method !== 'GET') {
    const origin = req.headers.get('origin');
    if (origin && origin !== url.origin) return err(403, 'Origem não permitida.');
  }

  if (path === '/api/register' && method === 'POST') {
    const b = await readJson(req);
    const username = String(b.username || '').trim().toLowerCase();
    const name = String(b.name || '').trim().slice(0, 60);
    const password = String(b.password || '');
    if (!/^[a-z0-9._-]{3,30}$/.test(username))
      return err(400, 'O usuário precisa ter de 3 a 30 caracteres: letras, números, ponto, hífen ou sublinhado.');
    if (!name) return err(400, 'Informe seu nome.');
    if (password.length < 6) return err(400, 'A senha precisa ter pelo menos 6 caracteres.');
    const exists = await env.DB.prepare('SELECT 1 FROM users WHERE username = ?').bind(username).first();
    if (exists) return err(409, 'Esse usuário já existe. Escolha outro.');
    const id = randHex(10);
    const salt = randHex(16);
    const hash = await hashPassword(password, salt);
    await env.DB.prepare('INSERT INTO users (id, username, name, pass_hash, salt, created_at) VALUES (?, ?, ?, ?, ?, ?)')
      .bind(id, username, name, hash, salt, now()).run();
    await createRoom(env, id, `Casa de ${name.split(' ')[0]}`);
    const token = await startSession(env, id);
    return json({ ok: true }, 200, { 'set-cookie': sessionCookie(token, SESSION_DAYS * 86400) });
  }

  if (path === '/api/login' && method === 'POST') {
    const b = await readJson(req);
    const username = String(b.username || '').trim().toLowerCase();
    const password = String(b.password || '');
    const u = await env.DB.prepare('SELECT id, pass_hash, salt FROM users WHERE username = ?').bind(username).first();
    const hash = await hashPassword(password, u ? u.salt : '00'.repeat(16));
    if (!u || !safeEqual(hash, u.pass_hash)) return err(401, 'Usuário ou senha incorretos.');
    const token = await startSession(env, u.id);
    return json({ ok: true }, 200, { 'set-cookie': sessionCookie(token, SESSION_DAYS * 86400) });
  }

  if (path === '/api/logout' && method === 'POST') {
    const token = getCookie(req, 'fc_sess');
    if (token) await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
    return json({ ok: true }, 200, { 'set-cookie': sessionCookie('', 0) });
  }

  const me = await currentUser(req, env);
  if (!me) return err(401, 'Entre com seu usuário e senha.');

  if (path === '/api/me' && method === 'GET') {
    const { results } = await env.DB.prepare(
      `SELECT r.id, r.name, m.role, r.owner_id,
              (SELECT COUNT(*) FROM members m2 WHERE m2.room_id = r.id) AS members
         FROM members m JOIN rooms r ON r.id = m.room_id
        WHERE m.user_id = ? ORDER BY m.joined_at`,
    ).bind(me.id).all();
    return json({ user: { id: me.id, username: me.username, name: me.name }, rooms: results });
  }

  if (path === '/api/password' && method === 'POST') {
    const b = await readJson(req);
    const u = await env.DB.prepare('SELECT pass_hash, salt FROM users WHERE id = ?').bind(me.id).first();
    if (!safeEqual(await hashPassword(String(b.current || ''), u.salt), u.pass_hash)) return err(400, 'A senha atual está incorreta.');
    if (String(b.next || '').length < 6) return err(400, 'A nova senha precisa ter pelo menos 6 caracteres.');
    const salt = randHex(16);
    await env.DB.batch([
      env.DB.prepare('UPDATE users SET pass_hash = ?, salt = ? WHERE id = ?').bind(await hashPassword(String(b.next), salt), salt, me.id),
      env.DB.prepare('DELETE FROM sessions WHERE user_id = ? AND token != ?').bind(me.id, me.token),
    ]);
    return json({ ok: true });
  }

  if (path === '/api/rooms' && method === 'POST') {
    const b = await readJson(req);
    const name = String(b.name || '').trim().slice(0, 60);
    if (!name) return err(400, 'Dê um nome para a sala.');
    const id = await createRoom(env, me.id, name);
    return json({ id });
  }

  // ---------- convites ----------
  let m = path.match(/^\/api\/invites\/([A-Za-z0-9]{8})(\/accept)?$/);
  if (m) {
    const code = m[1].toUpperCase();
    const inv = await env.DB.prepare(
      `SELECT i.code, i.room_id, i.expires_at, i.used_by, r.name AS room_name, u.name AS from_name,
              (SELECT COUNT(*) FROM members WHERE room_id = i.room_id) AS members
         FROM invites i JOIN rooms r ON r.id = i.room_id JOIN users u ON u.id = i.created_by
        WHERE i.code = ?`,
    ).bind(code).first();
    if (!inv) return err(404, 'Código não encontrado. Confira as letras e números.');
    if (inv.used_by) return err(410, 'Esse código já foi usado. Peça um novo.');
    if (inv.expires_at < now()) return err(410, 'Esse código expirou. Peça um novo.');
    const already = await membership(env, inv.room_id, me.id);
    if (!m[2] && method === 'GET') {
      return json({ code, room_id: inv.room_id, room_name: inv.room_name, from_name: inv.from_name, members: inv.members, already: !!already });
    }
    if (m[2] && method === 'POST') {
      if (already) return json({ room_id: inv.room_id, already: true });
      const t = now();
      const r = await env.DB.prepare('UPDATE invites SET used_by = ?, used_at = ? WHERE code = ? AND used_by IS NULL')
        .bind(me.id, t, code).run();
      if (!r.meta.changes) return err(410, 'Esse código já foi usado. Peça um novo.');
      await env.DB.prepare('INSERT OR IGNORE INTO members (room_id, user_id, role, joined_at) VALUES (?, ?, ?, ?)')
        .bind(inv.room_id, me.id, 'membro', t).run();
      return json({ room_id: inv.room_id });
    }
    return err(405, 'Método não permitido.');
  }

  // ---------- salas ----------
  m = path.match(/^\/api\/rooms\/([a-f0-9]{20})(\/[a-z]+)?(\/[a-f0-9]{20})?$/);
  if (m) {
    const roomId = m[1];
    const sub = m[2] || '';
    const role = await membership(env, roomId, me.id);
    if (!role) return err(404, 'Sala não encontrada ou você não faz parte dela.');
    const isOwner = role.role === 'dono';

    if (!sub && method === 'GET') {
      const room = await getRoom(env, roomId);
      const since = Number(url.searchParams.get('v') || 0);
      if (since && since === room.version) return json({ changed: false, version: room.version });
      return json({
        changed: true,
        room: { id: room.id, name: room.name, version: room.version, updated_at: room.updated_at, data: JSON.parse(room.data), role: role.role },
        members: await roomMembers(env, roomId),
      });
    }

    if (!sub && method === 'PATCH') {
      if (!isOwner) return err(403, 'Só quem criou a sala pode renomeá-la.');
      const b = await readJson(req);
      const name = String(b.name || '').trim().slice(0, 60);
      if (!name) return err(400, 'Dê um nome para a sala.');
      await env.DB.prepare('UPDATE rooms SET name = ? WHERE id = ?').bind(name, roomId).run();
      return json({ ok: true });
    }

    if (!sub && method === 'DELETE') {
      if (!isOwner) return err(403, 'Só quem criou a sala pode apagá-la.');
      const count = await env.DB.prepare('SELECT COUNT(*) AS n FROM members WHERE user_id = ?').bind(me.id).first();
      if (count.n <= 1) return err(400, 'Você precisa ter pelo menos uma sala.');
      await env.DB.batch([
        env.DB.prepare('DELETE FROM rooms WHERE id = ?').bind(roomId),
        env.DB.prepare('DELETE FROM members WHERE room_id = ?').bind(roomId),
        env.DB.prepare('DELETE FROM invites WHERE room_id = ?').bind(roomId),
      ]);
      return json({ ok: true });
    }

    if (sub === '/ops' && method === 'POST') {
      const b = await readJson(req);
      const ops = Array.isArray(b.ops) ? b.ops.slice(0, 500) : [];
      for (let attempt = 0; attempt < 6; attempt++) {
        const room = await getRoom(env, roomId);
        const data = Object.assign(emptyData(), JSON.parse(room.data));
        for (const c of COLS) if (!Array.isArray(data[c])) data[c] = [];
        applyOps(data, ops, me.id);
        const text = JSON.stringify(data);
        if (text.length > MAX_DATA) return err(413, 'A sala atingiu o limite de dados. Apague lançamentos antigos.');
        const r = await env.DB.prepare(
          'UPDATE rooms SET data = ?, version = version + 1, updated_at = ?, updated_by = ? WHERE id = ? AND version = ?',
        ).bind(text, now(), me.id, roomId, room.version).run();
        if (r.meta.changes) return json({ version: room.version + 1, data });
      }
      return err(503, 'Muitas alterações ao mesmo tempo. Tente de novo.');
    }

    if (sub === '/invites' && method === 'POST') {
      const t = now();
      let code;
      for (let i = 0; i < 5; i++) {
        code = inviteCode();
        const r = await env.DB.prepare('INSERT OR IGNORE INTO invites (code, room_id, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?)')
          .bind(code, roomId, me.id, t, t + INVITE_DAYS * 864e5).run();
        if (r.meta.changes) return json({ code, expires_at: t + INVITE_DAYS * 864e5 });
      }
      return err(503, 'Não consegui gerar um código. Tente de novo.');
    }

    if (sub === '/members' && m[3] && method === 'DELETE') {
      const target = m[3].slice(1);
      if (target !== me.id && !isOwner) return err(403, 'Só quem criou a sala pode remover outras pessoas.');
      const trg = await membership(env, roomId, target);
      if (!trg) return err(404, 'Essa pessoa não está na sala.');
      if (trg.role === 'dono') return err(400, 'Quem criou a sala não pode sair dela. Você pode apagá-la.');
      await env.DB.prepare('DELETE FROM members WHERE room_id = ? AND user_id = ?').bind(roomId, target).run();
      return json({ ok: true });
    }
  }

  return err(404, 'Rota não encontrada.');
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname.startsWith('/api/')) {
      try {
        return await handleApi(req, env, url);
      } catch (e) {
        console.error(e);
        return err(500, 'Erro no servidor. Tente de novo em instantes.');
      }
    }
    return env.ASSETS.fetch(req);
  },
};
