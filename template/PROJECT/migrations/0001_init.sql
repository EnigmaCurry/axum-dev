-- users
CREATE TABLE IF NOT EXISTS users (
  id           TEXT PRIMARY KEY NOT NULL, -- UUID as text
  email        TEXT UNIQUE NOT NULL,
  display_name TEXT NOT NULL,
  created_at   INTEGER NOT NULL           -- unix seconds
);

-- todos
CREATE TABLE IF NOT EXISTS todos (
  id          TEXT PRIMARY KEY NOT NULL,  -- UUID as text
  user_id     TEXT NOT NULL,
  title       TEXT NOT NULL,
  notes       TEXT,
  completed   INTEGER NOT NULL DEFAULT 0, -- 0/1
  due_at      INTEGER,                    -- nullable unix seconds
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL,

  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS todos_user_id_idx ON todos(user_id);
