-- Migração: separa a tabela app_data por usuário (antes era 1 linha fixa id=1 compartilhada por todos)
-- Rodar: npx wrangler d1 execute plantao --remote --file=./migration_002_dados_por_usuario.sql

PRAGMA foreign_keys=off;

CREATE TABLE app_data_new (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  usuario_id INTEGER NOT NULL UNIQUE REFERENCES usuarios(id) ON DELETE CASCADE,
  meses TEXT NOT NULL DEFAULT '{}',
  atualizado_em TEXT NOT NULL
);

-- Atribui os dados que já existem na linha antiga (id=1) ao usuário não-admin,
-- já que foi ele quem usou o app por último e sobrescreveu os dados compartilhados.
INSERT INTO app_data_new (usuario_id, meses, atualizado_em)
SELECT (SELECT id FROM usuarios WHERE role != 'admin' ORDER BY id LIMIT 1), meses, atualizado_em
FROM app_data WHERE id = 1
  AND EXISTS (SELECT 1 FROM usuarios WHERE role != 'admin');

-- Cria uma linha vazia para cada usuário que ainda não tem dados próprios (ex: o admin)
INSERT INTO app_data_new (usuario_id, meses, atualizado_em)
SELECT u.id, '{}', datetime('now')
FROM usuarios u
WHERE u.id NOT IN (SELECT usuario_id FROM app_data_new);

DROP TABLE app_data;
ALTER TABLE app_data_new RENAME TO app_data;

PRAGMA foreign_keys=on;
