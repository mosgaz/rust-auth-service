# rust-auth-service

[Техническое задание](docs/SPECIFICATION.md)

Базовый каркас сервиса аутентификации (v4.0) на `Axum` с упором на:

- чистую модульную структуру (`domain`, `api`, `security`, `config`);
- типизированные идентификаторы (`UserId`, `TenantId`, `FamilyId`, `InviteId`);
- основные технические endpoints:
  - `GET /health/live`
  - `GET /health/ready`
  - `GET /.well-known/jwks.json`
- утилиту SHA-256 хеширования токенов для хранения `refresh/reset/invite` в хешированном виде.

## Запуск

```bash
cargo run
```

Переменные окружения:

- `AUTH_HOST` (по умолчанию `0.0.0.0`)
- `AUTH_PORT` (по умолчанию `8080`)
- `AUTH_ISSUER` (по умолчанию `https://auth.example.com`)

## Проверка

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

## Дальнейшие шаги

1. Подключить PostgreSQL/Redis и миграции SQLx.
2. Реализовать полноценный `JWT signing + key rotation + JWKS`.
3. Добавить use-cases: login/refresh/logout/invites.
4. Добавить idempotency-хранилище и бизнес-транзакции.
