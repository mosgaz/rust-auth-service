# rust-auth-service — документация для GitHub Pages

> Версия документа: 1.0  
> Актуально для ветки с обновлениями от 2026-02-20.

## 1. Назначение сервиса

`rust-auth-service` — сервис аутентификации на базе `Axum`, предоставляющий:

- регистрацию и логин пользователей;
- выпуск `access/refresh` JWT-токенов (`RS256`);
- ротацию refresh-токенов и защиту от reuse;
- логаут текущей сессии и логаут всех сессий;
- восстановление/подтверждение сброса пароля;
- управление сессиями устройств (просмотр, удаление, trust-флаг);
- инвайт-флоу в tenant (создание, принятие, список, удаление);
- внутренние endpoint-ы для lookup/verify интеграций.

## 2. Быстрый старт

### Требования

- Rust toolchain (`stable`)
- Cargo

### Запуск

```bash
cargo run
```

По умолчанию сервис поднимается на `0.0.0.0:8080`.

### Переменные окружения

- `AUTH_HOST` — хост (default: `0.0.0.0`)
- `AUTH_PORT` — порт (default: `8080`)
- `AUTH_ISSUER` — issuer для JWT (default: `https://auth.example.com`)
- `DATABASE_URL` — строка подключения к Postgres (опционально)
- `REDIS_URL` — строка подключения к Redis (опционально)

## 3. Архитектура

Ключевые модули:

- `src/main.rs` — старт приложения, bind listener, запуск HTTP-сервера.
- `src/api/mod.rs` — маршруты, DTO и in-memory реализация бизнес-логики.
- `src/security/mod.rs` — JWT, JWK/JWKS, password/token hashing.
- `src/config.rs` — загрузка конфигурации из env.

Состояние приложения (`AppState`) хранится in-memory (HashMap/RwLock), что подходит для локальной разработки и интеграционных тестов.

## 4. API (основные endpoint-ы)

## Health

- `GET /health/live`
- `GET /health/ready`

## JWT metadata

- `GET /.well-known/jwks.json`

## Auth

- `POST /auth/register`
- `POST /auth/login` (поддерживает `Idempotency-Key`)
- `POST /auth/refresh`
- `POST /auth/logout` (`refresh_token` или `family_id`)
- `POST /auth/logout-all`
- `POST /auth/revoke-all` (алиас к logout-all)
- `POST /auth/restore` (**требуется** `Idempotency-Key`, ответ `202`)
- `POST /auth/reset-confirm` (**требуется** `Idempotency-Key`, ответ `200 {"success":true}`)

## Sessions / devices

- `GET /auth/sessions`
- `DELETE /auth/sessions/:family_id`
- `PATCH /auth/sessions/:family_id/trust`
- `POST /auth/sessions/push-token`
- `DELETE /auth/sessions/push-token`

## Invites and members

- `POST /api/tenants/:tenant_id/invites` (**требуется** `Idempotency-Key`)
- `GET /api/tenants/:tenant_id/invites`
- `DELETE /api/tenants/:tenant_id/invites/:invite_id`
- `POST /api/invites/accept`
- `GET /api/tenants/:tenant_id/members`
- `DELETE /api/tenants/:tenant_id/members/:user_id`
- `PATCH /api/tenants/:tenant_id/members/:user_id/status`

## Internal

- `GET /internal/users/:user_id/tenants`
- `POST /internal/verify-token`
- `POST /internal/users/lookup`

## 5. Безопасность

- Подпись JWT — `RS256`.
- JWKS публикуется через `/.well-known/jwks.json`.
- Access lifetime: `15 минут`.
- Refresh lifetime: `30 дней`.
- Reuse detection: при повторном использовании устаревшего refresh JTI сессия инвалидируется.
- Пароли хешируются с солью в формате `sha256$<salt>$<hash>`.

## 6. Миграции БД

В проекте есть SQLx-миграции:

- `migrations/202602200001_init.sql`
- `migrations/202602200002_expand_schema_to_spec.sql`
- `migrations/202602200003_gap_alignment.sql`

Текущая runtime-логика in-memory не зависит от активного подключения к Postgres, но схема и миграции подготовлены под целевую спецификацию.

## 7. Проверка работоспособности

Рекомендуемые проверки:

```bash
cargo fmt --check
cargo test
```

Интеграционный тест `tests/auth_integration.rs` покрывает полный базовый auth-flow новых endpoint-ов.

## 8. Публикация этой документации в GitHub Pages

Ниже вариант без генераторов (через ветку `gh-pages` и обычный Markdown/HTML).

### Шаг 1. Подготовить docs

Документация хранится в `docs/`.

### Шаг 2. Включить GitHub Pages

1. Откройте `Settings` репозитория.
2. Перейдите в `Pages`.
3. В `Build and deployment` выберите:
   - `Source: Deploy from a branch`
   - `Branch: main` (или `master`) и папку `/docs`.
4. Сохраните.

GitHub опубликует сайт по адресу вида:

`https://<org-or-user>.github.io/<repo>/`

### Шаг 3. (Опционально) Добавить index.md

Если хотите сделать стартовую страницу, используйте `docs/index.md` и добавьте ссылки на:

- спецификацию (`docs/SPECIFICATION.md`)
- gap-analysis (`docs/TZ_GAP_ANALYSIS.md`)
- этот файл (`docs/GITHUB_PAGES.md`)

### Шаг 4. Автообновление

При каждом push в основную ветку GitHub Pages будет автоматически обновлять опубликованную документацию.

## 9. Ограничения текущей реализации

- Данные приложения хранятся в памяти процесса; перезапуск очищает состояние.
- Нет фактической интеграции с БД/Redis в runtime-операциях.
- Секреты/ключи сейчас захардкожены в коде (для dev-режима); для production необходимо вынести в безопасный secret storage и внедрить ротацию ключей на инфраструктурном уровне.

## 10. Рекомендации перед production

- Перенести state на PostgreSQL/Redis.
- Подключить Argon2id для паролей.
- Реализовать полноценный аудит security events в БД/лог-стек.
- Добавить rate-limits, CAPTCHA/anti-abuse для auth endpoint-ов.
- Включить CI-пайплайн с `fmt`, `clippy`, `test`, `audit`.
