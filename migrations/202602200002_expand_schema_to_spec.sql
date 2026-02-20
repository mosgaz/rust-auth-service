-- Expand database schema to align with docs/SPECIFICATION.md section 3.

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY,
  status TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ,
  anonymized_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS identities (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id),
  type TEXT NOT NULL,
  value TEXT NOT NULL,
  is_verified BOOLEAN NOT NULL DEFAULT false,
  deleted_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_identities_type_value_active
  ON identities(type, value)
  WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS credentials (
  user_id UUID PRIMARY KEY REFERENCES users(id),
  password_hash TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tenant_members (
  user_id UUID NOT NULL REFERENCES users(id),
  tenant_id UUID NOT NULL,
  status TEXT NOT NULL,
  joined_at TIMESTAMPTZ,
  invited_by UUID,
  invited_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ,
  PRIMARY KEY (user_id, tenant_id)
);

CREATE TABLE IF NOT EXISTS device_push_tokens (
  user_id UUID NOT NULL REFERENCES users(id),
  family_id UUID NOT NULL REFERENCES refresh_sessions(family_id),
  push_token TEXT NOT NULL,
  platform TEXT NOT NULL,
  app_version TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, family_id)
);

CREATE TABLE IF NOT EXISTS password_resets (
  token_hash TEXT PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id),
  used_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE refresh_sessions
  ADD COLUMN IF NOT EXISTS device_info JSONB,
  ADD COLUMN IF NOT EXISTS device_name TEXT,
  ADD COLUMN IF NOT EXISTS device_type TEXT,
  ADD COLUMN IF NOT EXISTS user_agent TEXT,
  ADD COLUMN IF NOT EXISTS ip_address INET,
  ADD COLUMN IF NOT EXISTS is_current BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS is_trusted BOOLEAN NOT NULL DEFAULT false;

CREATE UNIQUE INDEX IF NOT EXISTS uq_refresh_sessions_jti_active
  ON refresh_sessions(current_jti_hash)
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS ix_refresh_sessions_user_active
  ON refresh_sessions(user_id)
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS ix_refresh_sessions_user_device_type
  ON refresh_sessions(user_id, device_type);

CREATE INDEX IF NOT EXISTS ix_refresh_sessions_last_active_at_desc
  ON refresh_sessions(last_active_at DESC);

ALTER TABLE pending_invites
  ADD COLUMN IF NOT EXISTS invited_by UUID;

ALTER TABLE idempotency_keys
  ADD COLUMN IF NOT EXISTS user_id UUID;

ALTER TABLE key_store
  ADD COLUMN IF NOT EXISTS tenant_id UUID;
