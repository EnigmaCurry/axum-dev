-- identity providers

CREATE TABLE identity_providers (
    id              INTEGER PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,  -- e.g. 'traefik-forwardauth', 'google', 'github'
    display_name    TEXT NOT NULL         -- human-readable
    -- you can add is_default INTEGER DEFAULT 0 CHECK (is_default IN (0,1)) if you like
);

INSERT INTO identity_providers (name, display_name)
VALUES
    ('system','System User'),
    ('traefik-forwardauth', 'Traefik ForwardAuth');


-- signup methods

CREATE TABLE signup_methods (
    id              INTEGER PRIMARY KEY,
    code            TEXT NOT NULL UNIQUE,  -- 'self', 'admin', 'import', 'api', ...
    description     TEXT NOT NULL
);

INSERT INTO signup_methods (code, description) VALUES
    ('self',  'User registered via web UI'),
    ('admin', 'Admin created the account manually');


-- users

CREATE TABLE users (
    id                   BLOB PRIMARY KEY, -- uuid (sqlx::types::Uuid)
    identity_provider_id INTEGER NOT NULL REFERENCES identity_providers(id),
    external_id          TEXT NOT NULL,   -- value from ForwardAuth (e.g. subject or email)

    email                TEXT NOT NULL,   -- email as given by ForwardAuth
    username             TEXT,            -- user-chosen username; see CHECK below

    is_registered        INTEGER NOT NULL DEFAULT 0
                         CHECK (is_registered IN (0,1)),
    registered_at        DATETIME DEFAULT (CURRENT_TIMESTAMP), -- auto-populate when omitted
    signup_method_id     INTEGER REFERENCES signup_methods(id),

    status               TEXT NOT NULL DEFAULT 'active'
                         CHECK (status IN ('active','disabled','banned')),

    created_at           DATETIME NOT NULL DEFAULT (CURRENT_TIMESTAMP),
    updated_at           DATETIME NOT NULL DEFAULT (CURRENT_TIMESTAMP),

    CHECK (
        (is_registered = 0 AND username IS NULL)
        OR
        (is_registered = 1 AND username IS NOT NULL)
    ),

    UNIQUE(identity_provider_id, external_id),
    UNIQUE(identity_provider_id, email),
    UNIQUE(username)
);

-- root user (system identity provider)
-- Note: we let SQLite default registered_at to CURRENT_TIMESTAMP.

INSERT OR IGNORE INTO users (
    id,
    identity_provider_id,
    external_id,
    email,
    username,
    is_registered,
    signup_method_id,
    status
)
VALUES (
    randomblob(16),  -- or insert a fixed UUID blob if you want this id stable
    (SELECT id FROM identity_providers WHERE name = 'system'),
    'root',                        -- external_id
    'root',                        -- email
    'root',                        -- username
    1,                             -- is_registered
    (SELECT id FROM signup_methods WHERE code = 'admin'),
    'active'
);


-- roles

CREATE TABLE roles (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,        -- 'unregistered', 'user', 'admin', ...
    description TEXT NOT NULL
);

INSERT INTO roles (name, description) VALUES
    ('user',         'Default registered user'),
    ('admin',        'Administrator with elevated permissions'),
    ('superadmin',   'Highest-level admin');


-- user_roles
-- IMPORTANT: user_id and assigned_by must match the type of users.id (BLOB)

CREATE TABLE user_roles (
    user_id         BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id         INTEGER NOT NULL REFERENCES roles(id),
    assigned_at     DATETIME NOT NULL DEFAULT (CURRENT_TIMESTAMP),
    assigned_by     BLOB REFERENCES users(id), -- which admin gave them this role

    PRIMARY KEY (user_id, role_id)
);

-- root is an admin, with system/system root user

INSERT OR IGNORE INTO user_roles (user_id, role_id, assigned_by)
SELECT u.id, r.id, NULL
FROM users u
JOIN identity_providers ip ON ip.id = u.identity_provider_id
JOIN roles r ON r.name = 'admin'
WHERE u.external_id = 'root'
  AND ip.name = 'system';
