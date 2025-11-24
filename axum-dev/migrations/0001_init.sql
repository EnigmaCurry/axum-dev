CREATE TABLE identity_providers (
    id              INTEGER PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,  -- e.g. 'traefik-forwardauth', 'google', 'github'
    display_name    TEXT NOT NULL,        -- human-readable
    is_default      INTEGER NOT NULL DEFAULT 0 CHECK (is_default IN (0,1))
);

INSERT INTO identity_providers (name, display_name, is_default)
VALUES ('traefik-forwardauth', 'Traefik ForwardAuth', 1);


CREATE TABLE signup_methods (
    id              INTEGER PRIMARY KEY,
    code            TEXT NOT NULL UNIQUE,  -- 'self', 'admin', 'import', 'api', ...
    description     TEXT NOT NULL
);

INSERT INTO signup_methods (code, description) VALUES
    ('self',  'User registered via web UI'),
    ('admin', 'Admin created the account manually');
CREATE TABLE users (
    id                   BLOB PRIMARY KEY, -- uuid (sqlx::types::Uuid)
    identity_provider_id INTEGER NOT NULL REFERENCES identity_providers(id),
    external_id          TEXT NOT NULL,   -- value from ForwardAuth (e.g. subject or email)

    email                TEXT NOT NULL,   -- email as given by ForwardAuth
    username             TEXT,            -- user-chosen username; see CHECK below

    is_registered        INTEGER NOT NULL DEFAULT 0
                         CHECK (is_registered IN (0,1)),
    registered_at        DATETIME,        -- when they clicked "Sign Me Up"
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

CREATE TABLE roles (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,        -- 'unregistered', 'user', 'admin', ...
    description TEXT NOT NULL
);

INSERT INTO roles (name, description) VALUES
    ('user',         'Default registered user'),
    ('admin',        'Administrator with elevated permissions'),
    ('superadmin',   'Highest-level admin');

CREATE TABLE user_roles (
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id         INTEGER NOT NULL REFERENCES roles(id),
    assigned_at     DATETIME NOT NULL DEFAULT (CURRENT_TIMESTAMP),
    assigned_by     INTEGER REFERENCES users(id), -- which admin gave them this role

    PRIMARY KEY (user_id, role_id)
);
