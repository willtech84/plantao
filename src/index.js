// Worker do Plantao — serve o app estatico (public/) e a API em /api/*
// Auth por sessao (token em D1), senha com PBKDF2 (Web Crypto, sem libs externas).

const SESSAO_DIAS = 30;
const SENHA_MIN = 4;
const RESET_HORAS = 24;
const RESET_MAX_TENTATIVAS = 5;

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
function isoDaquiHoras(horas) {
  return new Date(Date.now() + horas * 3600000).toISOString();
}
function igualConstante(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
function tokenDaRequisicao(req) {
  const auth = req.headers.get("Authorization") || "";
  return auth.startsWith("Bearer ") ? auth.slice(7) : null;
}

// Codigo de redefinicao: 8 caracteres sem ambiguos (sem 0/O, 1/I/L)
const ALFABETO_CODIGO = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
function gerarCodigo() {
  let out = "";
  const limite = 256 - (256 % ALFABETO_CODIGO.length);
  while (out.length < 8) {
    const arr = new Uint8Array(16);
    crypto.getRandomValues(arr);
    for (const b of arr) {
      if (b < limite && out.length < 8) out += ALFABETO_CODIGO[b % ALFABETO_CODIGO.length];
    }
  }
  return out;
}
function normalizarCodigo(c) {
  return String(c || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
}

// Cria a tabela de codigos na primeira vez que for usada (nao exige rodar migration manual)
let tabelaResetOk = false;
async function garantirTabelaReset(env) {
  if (tabelaResetOk) return;
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS redefinicoes_senha (
      usuario_id INTEGER PRIMARY KEY REFERENCES usuarios(id) ON DELETE CASCADE,
      codigo_hash TEXT NOT NULL,
      codigo_salt TEXT NOT NULL,
      expira_em TEXT NOT NULL,
      tentativas INTEGER NOT NULL DEFAULT 0,
      criado_em TEXT NOT NULL
    )`
  ).run();
  tabelaResetOk = true;
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

  // POST /redefinir-senha  (publico: e-mail + codigo gerado pelo admin + nova senha)
  if (path === "/redefinir-senha" && method === "POST") {
    const body = await req.json().catch(() => ({}));
    const email = (body.email || "").trim().toLowerCase();
    const codigo = normalizarCodigo(body.codigo);
    const nova = body.novaSenha || "";
    if (!email || !codigo) return erro("Informe o e-mail e o codigo.");
    if (nova.length < SENHA_MIN) return erro("A nova senha deve ter no minimo " + SENHA_MIN + " caracteres.");

    await garantirTabelaReset(env);
    const GENERICO = "Codigo invalido ou expirado. Peca um novo codigo ao administrador.";
    const u = await env.DB.prepare("SELECT id FROM usuarios WHERE email = ?").bind(email).first();
    if (!u) return erro(GENERICO);
    const r = await env.DB.prepare("SELECT * FROM redefinicoes_senha WHERE usuario_id = ?").bind(u.id).first();
    if (!r || r.expira_em <= new Date().toISOString() || r.tentativas >= RESET_MAX_TENTATIVAS) return erro(GENERICO);

    const hash = await hashSenha(codigo, r.codigo_salt);
    if (!igualConstante(hash, r.codigo_hash)) {
      await env.DB.prepare("UPDATE redefinicoes_senha SET tentativas = tentativas + 1 WHERE usuario_id = ?").bind(u.id).run();
      return erro(GENERICO);
    }

    const salt = randomHex();
    const novoHash = await hashSenha(nova, salt);
    await env.DB.batch([
      env.DB.prepare("UPDATE usuarios SET senha_hash = ?, senha_salt = ? WHERE id = ?").bind(novoHash, salt, u.id),
      env.DB.prepare("DELETE FROM redefinicoes_senha WHERE usuario_id = ?").bind(u.id),
      env.DB.prepare("DELETE FROM sessoes WHERE usuario_id = ?").bind(u.id),
    ]);
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
    if (usuario.role !== "admin") return erro("Apenas admin pode listar usuarios.", 403);
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

  // POST /alterar-senha  (usuario logado troca a propria senha)
  if (path === "/alterar-senha" && method === "POST") {
    const body = await req.json().catch(() => ({}));
    const atual = body.senhaAtual || "";
    const nova = body.novaSenha || "";
    if (!atual) return erro("Informe a senha atual.");
    if (nova.length < SENHA_MIN) return erro("A nova senha deve ter no minimo " + SENHA_MIN + " caracteres.");
    if (nova === atual) return erro("A nova senha deve ser diferente da atual.");

    const u = await env.DB.prepare("SELECT senha_hash, senha_salt FROM usuarios WHERE id = ?").bind(usuario.id).first();
    const hashAtual = await hashSenha(atual, u.senha_salt);
    if (!igualConstante(hashAtual, u.senha_hash)) return erro("Senha atual incorreta.", 403);

    const salt = randomHex();
    const novoHash = await hashSenha(nova, salt);
    // Troca a senha e derruba as outras sessoes (outros aparelhos); a atual continua valida
    await env.DB.batch([
      env.DB.prepare("UPDATE usuarios SET senha_hash = ?, senha_salt = ? WHERE id = ?").bind(novoHash, salt, usuario.id),
      env.DB.prepare("DELETE FROM sessoes WHERE usuario_id = ? AND token != ?").bind(usuario.id, tokenDaRequisicao(req) || ""),
    ]);
    return json({ ok: true });
  }

  // POST /usuarios/:id/codigo-reset  (admin gera codigo para o usuario que esqueceu a senha)
  const mReset = path.match(/^\/usuarios\/(\d+)\/codigo-reset$/);
  if (mReset && method === "POST") {
    if (usuario.role !== "admin") return erro("Apenas admin pode gerar codigos.", 403);
    const alvo = await env.DB.prepare("SELECT id FROM usuarios WHERE id = ?").bind(Number(mReset[1])).first();
    if (!alvo) return erro("Usuario nao encontrado.", 404);

    await garantirTabelaReset(env);
    const codigo = gerarCodigo();
    const salt = randomHex();
    const hash = await hashSenha(codigo, salt);
    const expiraEm = isoDaquiHoras(RESET_HORAS);
    await env.DB.prepare(
      `INSERT INTO redefinicoes_senha (usuario_id, codigo_hash, codigo_salt, expira_em, tentativas, criado_em)
       VALUES (?, ?, ?, ?, 0, ?)
       ON CONFLICT(usuario_id) DO UPDATE SET codigo_hash = excluded.codigo_hash, codigo_salt = excluded.codigo_salt,
         expira_em = excluded.expira_em, tentativas = 0, criado_em = excluded.criado_em`
    ).bind(alvo.id, hash, salt, expiraEm, new Date().toISOString()).run();
    return json({ codigo: codigo.slice(0, 4) + "-" + codigo.slice(4), horas: RESET_HORAS, expiraEm });
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
