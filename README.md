# rust-auth-service

[Техническое задание](docs/SPECIFICATION.md)

Сервис аутентификации на `Axum` с реализацией:

- JWT (`RS256`) с подписью, валидацией refresh-токенов, ротацией ключа подписи и выдачей `JWKS`;
- use-cases: `login`, `refresh`, `logout`, `invites`;
- идемпотентность для `login` через `Idempotency-Key`;
- заготовленные SQLx-миграции для PostgreSQL (`refresh_sessions`, `pending_invites`, `idempotency_keys`, `key_store`);
- интеграционный HTTP-тест полного auth-flow.

## Запуск

```bash
cargo run
```

Переменные окружения:

- `AUTH_HOST` (по умолчанию `0.0.0.0`)
- `AUTH_PORT` (по умолчанию `8080`)
- `AUTH_ISSUER` (по умолчанию `https://auth.example.com`)
- `DATABASE_URL` (опционально)
- `REDIS_URL` (опционально)

## Проверка

```bash
cargo fmt --check
cargo test
```
