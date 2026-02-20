# Анализ расхождений с ТЗ (v4.0)

Сводка по текущей реализации `rust-auth-service` относительно `docs/SPECIFICATION.md`.

## Критически не реализовано

1. **PostgreSQL/Redis интеграция отсутствует в runtime**
   - Сервис хранит пользователей, сессии, инвайты, reset-токены и idempotency ключи в in-memory структурах (`HashMap`/`HashSet`) внутри `AppState`.
   - Настройки `DATABASE_URL` и `REDIS_URL` только читаются и логируются, но не используются для подключения.

2. **Token rotation без reuse detection по семье токенов**
   - Есть проверка только на совпадение `current_jti_hash` в одной записи сессии.
   - При reuse нет инвалидации всей семьи токенов и нет событий безопасности.

3. **Отсутствует blacklist и graceful degradation**
   - Нет Redis blacklist, in-memory fallback LRU/TTL, буферизации записей при падении Redis.

4. **Пароли не хешируются Argon2id**
   - Пароль сохраняется и сравнивается как plain text.

## API расхождения с контрактом ТЗ

1. **`POST /auth/login`**
   - По ТЗ запрос содержит `device_name`, `device_type`, `device_info`; в коде принимаются только `identity`, `password`, `tenant_id`.
   - Идемпотентность реализована для login, тогда как в ТЗ обязательна для `/auth/restore`, `/auth/reset-confirm`, `/api/tenants/{tenant_id}/invites`.

2. **`POST /auth/logout`**
   - По ТЗ принимает `refresh_token` (опционально), в коде принимает обязательный `family_id`.

3. **`GET /auth/sessions`**
   - По ТЗ возвращает расширенные данные устройства/активности; в коде возвращается только список `family_id`.

4. **`PATCH /auth/sessions/{family_id}/trust`**
   - Эндпоинт заглушка, всегда `204`, без изменения trust-статуса.

5. **`POST /api/tenants/{tenant_id}/invites`**
   - По ТЗ обязателен `Idempotency-Key`, в коде не проверяется.
   - Формат ответа не совпадает (по ТЗ: `user_id`, `is_new`, `invite_id`; в коде: `invite_id`, `invite_token`, `expires_at`).

6. **`POST /api/invites/accept`**
   - По ТЗ поле `token` и ответ 200 c tenant-данными; в коде поле `invite_token` и ответ `204`.

7. **`POST /auth/restore` и `POST /auth/reset-confirm`**
   - По ТЗ обязательный `Idempotency-Key`; в коде отсутствует.
   - По ТЗ `/auth/restore` возвращает `202 Accepted` всегда, в коде `200` и отдает `reset_token` в ответе.
   - По ТЗ `/auth/reset-confirm` возвращает `200` с JSON `{ "success": true }`, в коде `204 No Content`.

8. **Защищенные эндпоинты**
   - В ТЗ часть эндпоинтов требует аутентификацию, но middleware/проверка доступа практически отсутствуют.

## JWT и ключи

1. **JWT claims не соответствуют spec-именам**
   - В ТЗ ожидаются поля `tid` и `fam`; в коде используются `tenant_id` и `family_id`.

2. **Key rotation частично/формально**
   - Есть только один встроенный статический RSA ключ; `rotate()` переключает индекс в массиве ключей, но без генерации/хранения новых ключей, grace-period и lifecycle по `kid`.

## База данных (схема)

1. **Нет таблицы `tenants` в миграциях**, хотя она обязательна по ТЗ.
2. **`key_store` не соответствует полям ТЗ**: вместо `expires_at` и `revoked_at` есть `is_active`.
3. **`refresh_sessions` использует `current_jti_hash`, а в ТЗ `current_jti` (хеш по описанию допускается, но naming расходится).**

## Наблюдаемость и эксплуатационные требования

1. **Readiness probe формальная**
   - `GET /health/ready` не проверяет доступность БД/Redis.

2. **Метрики и трассировка не реализованы**
   - Нет Prometheus метрик, trace propagation (`X-Request-ID`/`traceparent`) и спанов критических операций.

3. **События безопасности и retry/circuit-breaker политики отсутствуют**
   - Нет реализации сценариев из разделов 10.7 и 11.

## Частично реализовано

- Есть JWKS endpoint (`/.well-known/jwks.json`) и RS256 подпись JWT.
- Реализованы основные auth endpoints (`login/refresh/logout`) и часть invite/members endpoint-ов.
- Есть миграции для большинства таблиц из ТЗ (кроме `tenants`), но runtime-слой не использует БД.
