-- ============================================
-- Test data for identity_providers
-- ============================================
INSERT OR IGNORE INTO identity_providers (name, display_name, is_default)
VALUES
  ('traefik-forwardauth', 'Traefik ForwardAuth', 1),
  ('google',              'Google OAuth',        0),
  ('github',              'GitHub OAuth',        0);

-- ============================================
-- Test data for signup_methods
-- ============================================
INSERT OR IGNORE INTO signup_methods (code, description)
VALUES
  ('self',   'User registered via web UI'),
  ('admin',  'Admin created the account manually'),
  ('import', 'Imported from external system'),
  ('api',    'Created via API');

-- ============================================
-- Test data for roles
-- ============================================
INSERT OR IGNORE INTO roles (name, description)
VALUES
  ('user',       'Default registered user'),
  ('admin',      'Administrator with elevated permissions'),
  ('superadmin', 'Highest-level admin'),
  ('support',    'Support staff role');

-- ============================================
-- Test users
--
-- Notes:
--  - Some are registered, some are not.
--  - Mix of providers & signup methods.
--  - A few disabled/banned accounts.
-- ============================================

-- 1) Alice – registered user via self-signup, traefik-forwardauth
INSERT OR IGNORE INTO users (
    identity_provider_id,
    external_id,
    email,
    username,
    is_registered,
    registered_at,
    signup_method_id,
    status
)
VALUES (
    (SELECT id FROM identity_providers WHERE name = 'traefik-forwardauth'),
    'alice@example.com',           -- external_id
    'alice@example.com',           -- email
    'alice',                       -- username
    1,                             -- is_registered
    '2024-01-15 10:00:00',         -- registered_at
    (SELECT id FROM signup_methods WHERE code = 'self'),
    'active'
);

-- 2) Bob – registered user via self-signup, google
INSERT OR IGNORE INTO users (
    identity_provider_id,
    external_id,
    email,
    username,
    is_registered,
    registered_at,
    signup_method_id,
    status
)
VALUES (
    (SELECT id FROM identity_providers WHERE name = 'google'),
    'bob@gmail.com',
    'bob@gmail.com',
    'bobby',
    1,
    '2024-02-01 09:30:00',
    (SELECT id FROM signup_methods WHERE code = 'self'),
    'active'
);

-- 3) Carol – admin created via traefik-forwardauth
INSERT OR IGNORE INTO users (
    identity_provider_id,
    external_id,
    email,
    username,
    is_registered,
    registered_at,
    signup_method_id,
    status
)
VALUES (
    (SELECT id FROM identity_providers WHERE name = 'traefik-forwardauth'),
    'carol@example.com',
    'carol@example.com',
    'carol',
    1,
    '2024-02-10 14:45:00',
    (SELECT id FROM signup_methods WHERE code = 'admin'),
    'active'
);

-- 4) Dave – superadmin via admin creation, github
INSERT OR IGNORE INTO users (
    identity_provider_id,
    external_id,
    email,
    username,
    is_registered,
    registered_at,
    signup_method_id,
    status
)
VALUES (
    (SELECT id FROM identity_providers WHERE name = 'github'),
    'dave@github',
    'dave@github',
    'dave',
    1,
    '2024-03-05 08:15:00',
    (SELECT id FROM signup_methods WHERE code = 'admin'),
    'active'
);

-- 5) Eve – unregistered user (has logged in via ForwardAuth but never clicked "Sign Me Up")
INSERT OR IGNORE INTO users (
    identity_provider_id,
    external_id,
    email,
    username,
    is_registered,
    registered_at,
    signup_method_id,
    status
)
VALUES (
    (SELECT id FROM identity_providers WHERE name = 'traefik-forwardauth'),
    'eve@example.com',
    'eve@example.com',
    NULL,            -- no username yet
    0,               -- is_registered
    NULL,            -- registered_at
    NULL,            -- signup_method_id
    'active'
);

-- 6) Frank – disabled account (was registered)
INSERT OR IGNORE INTO users (
    identity_provider_id,
    external_id,
    email,
    username,
    is_registered,
    registered_at,
    signup_method_id,
    status
)
VALUES (
    (SELECT id FROM identity_providers WHERE name = 'traefik-forwardauth'),
    'frank@example.com',
    'frank@example.com',
    'frank',
    1,
    '2024-01-20 11:00:00',
    (SELECT id FROM signup_methods WHERE code = 'self'),
    'disabled'
);

-- 7) Grace – banned user
INSERT OR IGNORE INTO users (
    identity_provider_id,
    external_id,
    email,
    username,
    is_registered,
    registered_at,
    signup_method_id,
    status
)
VALUES (
    (SELECT id FROM identity_providers WHERE name = 'google'),
    'grace@gmail.com',
    'grace@gmail.com',
    'grace',
    1,
    '2024-02-20 16:20:00',
    (SELECT id FROM signup_methods WHERE code = 'self'),
    'banned'
);

-- 8) Heidi – support staff created via import
INSERT OR IGNORE INTO users (
    identity_provider_id,
    external_id,
    email,
    username,
    is_registered,
    registered_at,
    signup_method_id,
    status
)
VALUES (
    (SELECT id FROM identity_providers WHERE name = 'traefik-forwardauth'),
    'heidi@example.com',
    'heidi@example.com',
    'heidi',
    1,
    '2024-03-01 12:00:00',
    (SELECT id FROM signup_methods WHERE code = 'import'),
    'active'
);

-- 9) Ivan – API-created admin on github
INSERT OR IGNORE INTO users (
    identity_provider_id,
    external_id,
    email,
    username,
    is_registered,
    registered_at,
    signup_method_id,
    status
)
VALUES (
    (SELECT id FROM identity_providers WHERE name = 'github'),
    'ivan@github',
    'ivan@github',
    'ivan',
    1,
    '2024-03-10 13:00:00',
    (SELECT id FROM signup_methods WHERE code = 'api'),
    'active'
);

-- 10) Judy – registered user on traefik, no special roles
INSERT OR IGNORE INTO users (
    identity_provider_id,
    external_id,
    email,
    username,
    is_registered,
    registered_at,
    signup_method_id,
    status
)
VALUES (
    (SELECT id FROM identity_providers WHERE name = 'traefik-forwardauth'),
    'judy@example.com',
    'judy@example.com',
    'judy',
    1,
    '2024-03-12 09:00:00',
    (SELECT id FROM signup_methods WHERE code = 'self'),
    'active'
);

-- ============================================
-- User roles
--
-- We use (email, role-name) lookups so we don't depend on numeric IDs.
-- ============================================

-- Helper: assign a role to a user (pattern repeated)
-- Alice: user
INSERT OR IGNORE INTO user_roles (user_id, role_id, assigned_by)
SELECT
    u.id,
    r.id,
    NULL
FROM users u
JOIN roles r ON r.name = 'user'
WHERE u.email = 'alice@example.com';

-- Bob: user
INSERT OR IGNORE INTO user_roles (user_id, role_id, assigned_by)
SELECT
    u.id,
    r.id,
    NULL
FROM users u
JOIN roles r ON r.name = 'user'
WHERE u.email = 'bob@gmail.com';

-- Carol: user + admin
INSERT OR IGNORE INTO user_roles (user_id, role_id, assigned_by)
SELECT u.id, r.id, NULL
FROM users u
JOIN roles r ON r.name = 'user'
WHERE u.email = 'carol@example.com';

INSERT OR IGNORE INTO user_roles (user_id, role_id, assigned_by)
SELECT u.id, r.id, NULL
FROM users u
JOIN roles r ON r.name = 'admin'
WHERE u.email = 'carol@example.com';

-- Dave: user + admin + superadmin
INSERT OR IGNORE INTO user_roles (user_id, role_id, assigned_by)
SELECT u.id, r.id, NULL
FROM users u
JOIN roles r ON r.name = 'user'
WHERE u.email = 'dave@github';

INSERT OR IGNORE INTO user_roles (user_id, role_id, assigned_by)
SELECT u.id, r.id, NULL
FROM users u
JOIN roles r ON r.name = 'admin'
WHERE u.email = 'dave@github';

INSERT OR IGNORE INTO user_roles (user_id, role_id, assigned_by)
SELECT u.id, r.id, NULL
FROM users u
JOIN roles r ON r.name = 'superadmin'
WHERE u.email = 'dave@github';

-- Eve: no roles (unregistered) – intentionally left blank

-- Frank: user
INSERT OR IGNORE INTO user_roles (user_id, role_id, assigned_by)
SELECT u.id, r.id, NULL
FROM users u
JOIN roles r ON r.name = 'user'
WHERE u.email = 'frank@example.com';

-- Grace: user (banned, but still has role)
INSERT OR IGNORE INTO user_roles (user_id, role_id, assigned_by)
SELECT u.id, r.id, NULL
FROM users u
JOIN roles r ON r.name = 'user'
WHERE u.email = 'grace@gmail.com';

-- Heidi: user + support
INSERT OR IGNORE INTO user_roles (user_id, role_id, assigned_by)
SELECT u.id, r.id, NULL
FROM users u
JOIN roles r ON r.name = 'user'
WHERE u.email = 'heidi@example.com';

INSERT OR IGNORE INTO user_roles (user_id, role_id, assigned_by)
SELECT u.id, r.id, NULL
FROM users u
JOIN roles r ON r.name = 'support'
WHERE u.email = 'heidi@example.com';

-- Ivan: user + admin
INSERT OR IGNORE INTO user_roles (user_id, role_id, assigned_by)
SELECT u.id, r.id, NULL
FROM users u
JOIN roles r ON r.name = 'user'
WHERE u.email = 'ivan@github';

INSERT OR IGNORE INTO user_roles (user_id, role_id, assigned_by)
SELECT u.id, r.id, NULL
FROM users u
JOIN roles r ON r.name = 'admin'
WHERE u.email = 'ivan@github';

-- Judy: user
INSERT OR IGNORE INTO user_roles (user_id, role_id, assigned_by)
SELECT u.id, r.id, NULL
FROM users u
JOIN roles r ON r.name = 'user'
WHERE u.email = 'judy@example.com';
