-- Schema D1 para o app Plantao (ex-Sobreaviso)
-- Rodar: npx wrangler d1 execute plantao --remote --file=./schema.sql

CREATE TABLE IF NOT EXISTS usuarios (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nome TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  whatsapp TEXT,
  senha_hash TEXT NOT NULL,
  senha_salt TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  criado_em TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessoes (
  token TEXT PRIMARY KEY,
  usuario_id INTEGER NOT NULL,
  criado_em TEXT NOT NULL,
  expira_em TEXT NOT NULL,
  FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
);

-- Guarda o objeto "meses" (escalas/exames/corridas) inteiro, mesmo formato que ja existia no localStorage.
-- Uma linha por usuario (cada um ve e edita so os proprios dados).
CREATE TABLE IF NOT EXISTS app_data (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  usuario_id INTEGER NOT NULL UNIQUE REFERENCES usuarios(id) ON DELETE CASCADE,
  meses TEXT NOT NULL DEFAULT '{}',
  atualizado_em TEXT NOT NULL
);

-- Codigos de redefinicao de senha (gerados pelo admin; guardados com hash, uso unico).
-- O Worker tambem cria esta tabela sozinho na primeira vez que for usada (CREATE TABLE IF NOT EXISTS).
CREATE TABLE IF NOT EXISTS redefinicoes_senha (
  usuario_id INTEGER PRIMARY KEY REFERENCES usuarios(id) ON DELETE CASCADE,
  codigo_hash TEXT NOT NULL,
  codigo_salt TEXT NOT NULL,
  expira_em TEXT NOT NULL,
  tentativas INTEGER NOT NULL DEFAULT 0,
  criado_em TEXT NOT NULL
);
