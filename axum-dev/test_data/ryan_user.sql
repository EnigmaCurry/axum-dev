-- root user's local password: "password"
-- TODO: change this hardcoded dev password
-- bcrypt hash: $2a$12$CI.hSvuZLhl8I7et0Nkew.6UevgTB/cmaU./087Q1Svk2A/fqE.3C

INSERT INTO user_password (user_id, password_hash)
VALUES (
    'd5225232-bbee-4723-b0af-1526512fa098',
    '$2a$12$CI.hSvuZLhl8I7et0Nkew.6UevgTB/cmaU./087Q1Svk2A/fqE.3C'
) ON CONFLICT DO NOTHING;
