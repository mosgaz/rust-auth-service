# rust-auth-service

[Техническое задание](docs/SPECIFICATION.md)

# Сервис аутентификации (Auth Service)

Мультитенантный сервис аутентификации и управления доступом с поддержкой множественных устройств, безопасной ротацией токенов и graceful degradation.

## Ключевые возможности

- **Мультитенантность**: Полная изоляция данных между арендаторами
- **Безопасность**: Argon2id для паролей, token rotation, reuse detection, автоматическая ротация ключей JWT
- **Multidevice**: Управление сессиями устройств, push-уведомления, доверенные устройства
- **Приглашения**: Полный цикл инвайтов для существующих и новых пользователей
- **Идемпотентность**: Защита от дублирования операций через Idempotency-Key
- **Graceful degradation**: Работа с ограниченной функциональностью при отказе зависимостей (Redis, email)
- **Наблюдаемость**: Структурированные логи, метрики Prometheus, сквозная трассировка
- **GDPR compliance**: Мягкое удаление и анонимизация данных

## Архитектура

Проект следует принципам чистой архитектуры:
- **Domain Layer**: Бизнес-правила и сущности
- **Application Layer**: Сценарии использования
- **Infrastructure Layer**: PostgreSQL, Redis, внешние сервисы
- **API Layer**: HTTP обработчики, валидация

## Технологический стек

- **Язык**: Rust
- **Web Framework**: Axum
- **База данных**: PostgreSQL (SQLx с compile-time проверкой)
- **Кэш**: Redis
- **Логирование/трассировка**: tracing
- **Метрики**: metrics (Prometheus)
- **Криптография**: jsonwebtoken, rust-argon2

## Документация

Полное техническое задание доступно в [SPECIFICATION.md](docs/SPECIFICATION.md).

---
---
---

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
