// Worker do Plantao — serve o app estatico (public/) e a API em /api/*
// Auth por sessao (token em D1), senha com PBKDF2 (Web Crypto, sem libs externas).

const SESSAO_DIAS = 30;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}
function erro(msg, status = 400) {
  return json({ erro: msg }, status);
}

function bufToHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function randomHex(bytes = 16) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return bufToHex(arr);
}
async function hashSenha(senha, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(senha), { name: "PBKDF2" }, false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: enc.encode(salt), iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return bufToHex(bits);
}
function isoDaqui(dias) {
  return new Date(Date.now() + dias * 86400000).toISOString();
}

async function usuarioDaSessao(req, env) {
  const auth = req.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return null;
  const row = await env.DB.prepare(
    "SELECT u.id, u.nome, u.email, u.whatsapp, u.role, u.criado_em FROM sessoes s JOIN usuarios u ON u.id = s.usuario_id WHERE s.token = ? AND s.expira_em > ?"
  ).bind(token, new Date().toISOString()).first();
  return row || null;
}

function semSenha(u) {
  return { id: u.id, nome: u.nome, email: u.email, whatsapp: u.whatsapp, role: u.role, criadoEm: u.criado_em };
}

async function handleApi(req, env, url) {
  const path = url.pathname.replace(/^\/api/, "");
  const method = req.method;

  // POST /cadastro
  if (path === "/cadastro" && method === "POST") {
    const body = await req.json().catch(() => ({}));
    const nome = (body.nome || "").trim();
    const email = (body.email || "").trim().toLowerCase();
    const whatsapp = (body.whatsapp || "").trim();
    const senha = body.senha || "";
    if (!nome || !email || !senha || senha.length < 4) return erro("Preencha todos os campos (senha min. 4 caracteres).");

    const existe = await env.DB.prepare("SELECT id FROM usuarios WHERE email = ?").bind(email).first();
    if (existe) return erro("E-mail ja cadastrado.");

    const { count } = await env.DB.prepare("SELECT COUNT(*) as count FROM usuarios").first();
    const role = count === 0 ? "admin" : "user";
    const salt = randomHex();
    const hash = await hashSenha(senha, salt);
    const criadoEm = new Date().toLocaleDateString("pt-BR");

    const res = await env.DB.prepare(
      "INSERT INTO usuarios (nome, email, whatsapp, senha_hash, senha_salt, role, criado_em) VALUES (?,?,?,?,?,?,?)"
    ).bind(nome, email, whatsapp, hash, salt, role, criadoEm).run();
    const usuarioId = res.meta.last_row_id;

    const token = crypto.randomUUID();
    await env.DB.prepare("INSERT INTO sessoes (token, usuario_id, criado_em, expira_em) VALUES (?,?,?,?)")
      .bind(token, usuarioId, new Date().toISOString(), isoDaqui(SESSAO_DIAS)).run();

    return json({ token, usuario: { id: usuarioId, nome, email, whatsapp, role, criadoEm } });
  }

  // POST /login
  if (path === "/login" && method === "POST") {
    const body = await req.json().catch(() => ({}));
    const email = (body.email || "").trim().toLowerCase();
    const senha = body.senha || "";
    const u = await env.DB.prepare("SELECT * FROM usuarios WHERE email = ?").bind(email).first();
    if (!u) return erro("E-mail ou senha incorretos.", 401);
    const hash = await hashSenha(senha, u.senha_salt);
    if (hash !== u.senha_hash) return erro("E-mail ou senha incorretos.", 401);

    const token = crypto.randomUUID();
    await env.DB.prepare("INSERT INTO sessoes (token, usuario_id, criado_em, expira_em) VALUES (?,?,?,?)")
      .bind(token, u.id, new Date().toISOString(), isoDaqui(SESSAO_DIAS)).run();

    return json({ token, usuario: semSenha(u) });
  }

  // POST /logout
  if (path === "/logout" && method === "POST") {
    const auth = req.headers.get("Authorization") || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
    if (token) await env.DB.prepare("DELETE FROM sessoes WHERE token = ?").bind(token).run();
    return json({ ok: true });
  }

  // A partir daqui, todas as rotas exigem sessao valida
  const usuario = await usuarioDaSessao(req, env);
  if (!usuario) return erro("Sessao invalida ou expirada.", 401);

  // GET /me
  if (path === "/me" && method === "GET") {
    return json({ usuario: semSenha(usuario) });
  }

  // GET /usuarios
  if (path === "/usuarios" && method === "GET") {
    const { results } = await env.DB.prepare("SELECT id, nome, email, whatsapp, role, criado_em FROM usuarios ORDER BY id").all();
    return json({ usuarios: results.map(semSenha) });
  }

  // DELETE /usuarios/:id
  const mDel = path.match(/^\/usuarios\/(\d+)$/);
  if (mDel && method === "DELETE") {
    if (usuario.role !== "admin") return erro("Apenas admin pode excluir usuarios.", 403);
    const id = Number(mDel[1]);
    if (id === usuario.id) return erro("Voce nao pode excluir a si mesmo.");
    await env.DB.prepare("DELETE FROM usuarios WHERE id = ?").bind(id).run();
    return json({ ok: true });
  }

  // GET /dados
  if (path === "/dados" && method === "GET") {
    const row = await env.DB.prepare("SELECT meses, atualizado_em FROM app_data WHERE usuario_id = ?")
      .bind(usuario.id).first();
    return json({ meses: JSON.parse(row?.meses || "{}"), atualizadoEm: row?.atualizado_em || null });
  }

  // PUT /dados
  if (path === "/dados" && method === "PUT") {
    const body = await req.json().catch(() => null);
    if (!body || typeof body.meses !== "object") return erro("Corpo invalido, esperado { meses }.");
    await env.DB.prepare(
      `INSERT INTO app_data (usuario_id, meses, atualizado_em) VALUES (?, ?, ?)
       ON CONFLICT(usuario_id) DO UPDATE SET meses = excluded.meses, atualizado_em = excluded.atualizado_em`
    ).bind(usuario.id, JSON.stringify(body.meses), new Date().toISOString()).run();
    return json({ ok: true });
  }

  return erro("Rota nao encontrada.", 404);
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname.startsWith("/api/")) {
      try {
        return await handleApi(req, env, url);
      } catch (e) {
        return erro("Erro interno: " + (e && e.message ? e.message : String(e)), 500);
      }
    }
    return env.ASSETS.fetch(req);
  },
};
