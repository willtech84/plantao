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
-- Linha unica (id=1) porque o app e de uso compartilhado por toda a equipe.
CREATE TABLE IF NOT EXISTS app_data (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  meses TEXT NOT NULL DEFAULT '{}',
  atualizado_em TEXT NOT NULL
);

INSERT OR IGNORE INTO app_data (id, meses, atualizado_em) VALUES (1, '{}', datetime('now'));
