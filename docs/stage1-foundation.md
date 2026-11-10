# Foundation Controller

Пакет `hostorbit` реализует прикладной Stage1 Foundation. Его [приёмка по шести capabilities §40](../evidence/acceptance/stage1-2026-11-08/README.md) зафиксирована отдельно от полного MVP. Он предоставляет локальное создание Owner, серверную аутентификацию, scope RBAC, SQLite, Audit/Outbox и версионированный HTTP API. Лабораторный `stage0` остаётся самостоятельным набором доказательных прототипов.

## Установка для разработки

Для текущей разработки и CI используется Python 3.15 и локальный POSIX-том с SQLite 3.45 или новее. Пакет сохраняет минимум Python 3.13. Зависимости закреплены в `requirements-app.txt`; `requirements-dev.txt` добавляет средства испытаний.

```bash
python3.15 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m hostorbit --database "$PWD/.hostorbit-state/controller.sqlite3" init
.venv/bin/python -m hostorbit --database "$PWD/.hostorbit-state/controller.sqlite3" bootstrap-token
.venv/bin/python -m hostorbit --database "$PWD/.hostorbit-state/controller.sqlite3" create-owner --username roman
```

CLI показывает одноразовый token, действующий 10 минут. `create-owner` запрашивает token, пароль и повтор пароля скрытым вводом. Первый веб-посетитель не создаёт Owner. Повторная выдача token заменяет предыдущий, а потребление и создание Owner выполняются одной транзакцией. Аргументов командной строки для пароля и token нет.

Новые пароли должны содержать минимум 14 символов. `serve` запускается от непривилегированного пользователя; запуск API с UID 0 отклоняется.

Команда `serve --origin https://hostorbit.example` запускает API на `127.0.0.1:8000`. HTTPS завершается на явно настроенном reverse proxy. Если он передаёт схему и IP, его точный адрес или CIDR передаётся отдельным `--trusted-proxy`. Proxy должен перезаписывать `X-Forwarded-Proto` и `X-Forwarded-For` одним фактическим IP. Uvicorn proxy headers отключены. Без настроенного доверия используется peer IP и исходная схема соединения. Публичный DNS, TLS и Nginx этим кодом не меняются.

## Аутентификация и права

Пароли хешируются Argon2id с профилем 1 из `hostorbit/release-manifest.json` — 64 MiB, три прохода, четыре потока. При входе старый допустимый hash мигрирует на текущий профиль. Manifest обозначен как development и не включает удалённые изменения.

`POST /api/v1/auth/login` выдаёт cookie `__Host-hostorbit_session` с `Secure`, `HttpOnly`, `SameSite=Strict` и `Path=/`. Session ID меняется при входе. В SQLite сохраняются дайджесты session/CSRF. CSRF получен HMAC от конкретной сессии; чтение `/auth/session` возвращает тот же token, поэтому вкладки не отзывают его друг у друга. Выход отзывает текущую сессию, а изменение роли, grant или disabled — все сессии пользователя. Проверяются 30 минут простоя, 12 часов абсолютного срока и обратный ход наблюдаемого времени сессии.

`POST /api/v1/auth/reauth` проверяет пароль и выдаёт одноразовое подтверждение на пять минут с привязкой к session и точному `plan_hash`. Его потребляет будущая транзакция одобрения плана; сам этот endpoint не одобряет и не исполняет план.

Owner управляет прикладными правами. Admin использует делегированные scopes и передаёт только те grants, которыми обладает сам; Owner/Admin вне его полномочий скрыты. Operator получает только whitelist permissions на явно перечисленные ULID ресурсов; wildcard для него запрещён. Auditor имеет только чтение. Права секретов называются `View Metadata`, `Use`, `Manage`; API раскрытия значения секрета отсутствует.

`GET /api/v1/users` и `GET /api/v1/users/{id}` возвращают strong ETag. Создание требует If-Match коллекции, изменение — If-Match пользователя. Пропуск даёт 428, stale значение — 412. Изменение полномочий и отзыв сессий сохраняются атомарно. Менеджер повторно проверяет текущую сессию, CSRF и scope внутри транзакции записи.

## Границы HTTP

Изменяющие запросы требуют HTTPS, точный Origin и JSON. Предельное тело — 16 KiB, включая chunked requests. Вход ограничен 20 запросами на IP за 15 минут, в том числе при ошибке JSON/схемы, и пятью неудачами на account+IP. Re-auth допускает три попытки за 15 минут. Обычный API ограничен 120 запросами на пользователя и 600 на IP в минуту. Счётчики переживают перезапуск сервиса; ответ 429 содержит Retry-After.

Ошибки имеют `{code,message,correlation_id,details}`. Validation errors не включают input values и произвольные имена полей. Авторизованные Owner/Admin получают OpenAPI по `/api/v1/openapi.json`; публичных `/docs`, `/openapi.json` и `/register-admin` нет. API отвечает `Cache-Control: no-store`. `/healthz` сообщает только liveness процесса.

## SQLite и события

Инициализация выполняется явно. В приватном режиме каталог имеет mode 0700, файл БД — 0600. Для разных UID API и Worker явно задаются владелец и отдельная группа БД, directory mode 2770 и file mode 0660; права проверяются при каждом соединении. Symlink БД отклоняется. Соединения проверяют WAL, synchronous FULL, foreign keys ON, busy timeout 5000 и допустимую версию схемы. Отсутствующая БД не создаётся при запросе, неизвестная схема закрывает доступ.

Изменение состояния, hash chain Audit и Outbox сохраняются одной транзакцией. SQLite triggers отклоняют обычные UPDATE/DELETE Audit/Outbox. Проверка `Store.verify_audit()` сравнивает цепочку и соответствие Outbox. Backend остаётся внутри TCB и имеет доступ к application SQLite; защита от переписывающего всю БД root/Backend RCE этим механизмом не заявлена.

`GET /api/v1/audit` и `/api/v1/events` требуют `audit:read`. SSE отдаёт ограниченный пакет уже зафиксированных событий, поддерживает Last-Event-ID и переподключение EventSource. Автоматические подключения к `/events` не продлевают сессию по бездействию. Несохранённое состояние не становится событием. Доступ проверяется менеджером в том же read snapshot, из которого берутся события.

## Проверки и следующие capability

```bash
.venv/bin/python -m unittest discover -s tests_app -v
```

Тесты включают гонку bootstrap, реальный SIGKILL до commit, ошибку записи Outbox, конкурентные ETag updates, обход RBAC, отзыв сессий, CSRF, лимиты и подмену proxy headers. В CI выделен отдельный Python 3.15 job.

[Runtime contour](stage1-runtime.md) добавляет фиксированный read-only SSH probe через очередь, отдельные Worker/Broker и host authority. Browser получает только нормализованное наблюдение. [Development-установка](stage1-installation.md) разворачивает проверенный подписанный bundle; [репетиция миграции](stage1-migrations.md) работает с приватными копиями. Docker mutations, обновления и generic decrypt не входят в installed registry. Stage2 Change Plan/UI, live schema migration, полноценный production release и полные MVP AC остаются открытыми. Stage1 Foundation gate принят в ограниченном объёме §40; canonical registry и отдельные evidence определяют остальные переходы.
