# Анализ расхождений с ТЗ (v4.0)

Сводка по текущей реализации `rust-auth-service` относительно `docs/SPECIFICATION.md`.

## Закрыто в рамках доработки

1. **Ключевые API-контракты синхронизированы с ТЗ**
   - `POST /auth/logout` теперь принимает `refresh_token` (опционально).
   - `GET /auth/sessions` возвращает расширенные данные сессии (device info, trust, last active).
   - `PATCH /auth/sessions/{family_id}/trust` обновляет trust-флаг.
   - `POST /api/tenants/{tenant_id}/invites` проверяет обязательный `Idempotency-Key` и возвращает `user_id`, `is_new`, `invite_id`.
   - `POST /api/invites/accept` принимает поле `token` и возвращает `200` с данными о tenant membership.
   - `POST /auth/restore` требует `Idempotency-Key` и возвращает `202 Accepted` без reset-токена в ответе.
   - `POST /auth/reset-confirm` требует `Idempotency-Key` и возвращает `200` с JSON `{ "success": true }`.

2. **JWT claims приведены к naming из ТЗ**
   - Используются `tid` и `fam`.

3. **Пароли больше не хранятся в plain text**
   - В runtime пароли сохраняются в виде хеша (in-memory слой).

## Остаются критические расхождения

1. **PostgreSQL/Redis интеграция отсутствует в runtime**
   - Данные пользователей, сессий, инвайтов, reset-токенов и idempotency ключей по-прежнему in-memory.
   - `DATABASE_URL` и `REDIS_URL` только читаются из конфигурации.

2. **Token rotation без полной reuse-detection стратегии семейства**
   - Есть проверка `current_jti_hash` только в рамках конкретной записи сессии.
   - Нет инвалидации всей семьи токенов и security event pipeline.

3. **Blacklist + graceful degradation (Redis fallback) не реализованы**
   - Нет Redis blacklist и буферизации записей при отказах Redis.

4. **Требование Argon2id пока не выполнено полностью**
   - Используется хеширование в in-memory модели, но не полноценная схема Argon2id + policy lifecycle из ТЗ.

5. **Readiness / observability / эксплуатационные сценарии неполные**
   - `/health/ready` не проверяет доступность БД/Redis.
   - Нет Prometheus-метрик, trace propagation, security events и retry/circuit-breaker политик из разделов 10.7 и 11.

## Частично реализовано

- Есть JWKS endpoint (`/.well-known/jwks.json`) и RS256 подпись JWT.
- Реализованы основные auth/invite/member endpoint-ы.
- Есть миграции для большинства таблиц из ТЗ, но runtime-слой пока не использует БД.
