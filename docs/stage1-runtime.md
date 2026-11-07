# Наблюдение через Worker Broker и host authority

Stage1 получил первый прикладной сквозной контур. Авторизованный пользователь запрашивает проверку зарегистрированной VPS, Worker получает одноразовый допуск host authority, Broker проверяет собственный scope и использует SSH-ключ внутри своего процесса. Проверенный ответ становится результатом Job и событием Outbox.

Встроенный registry разрешает только `host.probe`. Он проверяет достижимость ограниченного root helper и возвращает `REACHABLE`, источник, время и boot ID. Это наблюдение не означает здоровье всех служб VPS. Docker restart, Nginx reload, обновления и другие инфраструктурные изменения остаются выключенными до реализации соответствующих preflight, Backup Gate и reconciliation controls. [Host TimeHealth](stage1-time-health.md) уже включён в mutating admission/consumption и maintenance transitions; production mutating registry остаётся закрытым.

## HTTP контракт

`POST /api/v1/resources/{resource_id}/observations` принимает пустой JSON объект, cookie-сессию, CSRF и `Idempotency-Key` длиной 16–128 из букв, цифр, дефиса или подчёркивания. Требуется отдельное право `vps:probe` на точную цель. Auditor с правом чтения не может создавать задания. HTTP 202 и Location выдаются после commit Job, Audit и Outbox.

Повтор ключа одним актором в namespace `host.probe` возвращает тот же Job в течение 24 часов. Другой payload даёт 409. Это дедупликация запроса наблюдения; она не определяет порядок исполнения будущих mutating Change Plans.

`GET /api/v1/jobs/{id}` проверяет текущее право `vps:read` до выдачи метаданных и возвращает strong ETag. Чужой Job скрыт как 404. В ответе нет GatePermit, ключа, generic stdout/stderr или Vault ciphertext. До успешного verify `observed_at` и `result` пусты.

## Допуски и состояние процессов

Authority хранит отдельный private SQLite journal. Permit подписан Ed25519 и содержит job/request identity, actor, target, capability, scope digest, dependency closure digest, epoch, nonce и срок до 60 секунд. Для read-only запроса поля plan/approval идентифицируют сам запрос наблюдения; утверждённого mutating плана у probe нет.

Broker сверяет подпись, время, target/scope, собственную protected policy и точную Secret Reference. Затем он сохраняет private intent и атомарно потребляет permit у authority до SSH. Только UID Broker может подтвердить результат; Worker не может выдать себе maintenance permit или сообщить authority собственный успех. Повтор nonce не исполняется.

TTL не освобождает mutating reservation в gate engine. Смерть процесса не удостоверяет завершение remote effects. `UNKNOWN_OUTCOME` остаётся терминальным для попытки. Engine исключает пересечение mutator и maintenance; для installed registry эти изменяющие adapters пока недоступны. Тестовый mutating adapter существует только в contract tests через локальную подмену registry.

При старте authority под lifetime lock восстанавливает журнал до приёма IPC. Незавершённый mutator или прерванный update оставляет `RECOVERY_HOLD`. Старый epoch не может потребить permit. Изменение host binding или protected policy закрывает authority; команды force-active нет. Скрытый полный clone не объявляется обнаруживаемым.

Worker держит kernel flock на весь срок жизни процесса. Только после получения этого lock он восстанавливает свои незавершённые claims. Для pre-dispatch отмены он проверяет authority и отзывает ещё не потреблённый permit. После возможного send сохраняются прежний Job ID, `UNKNOWN_OUTCOME` и отдельный OPEN incident. Поздний успешный receipt Broker не переписывает такой Job и не вызывает повторный SSH.

Runtime Worker явно обрабатывает SIGTERM/SIGINT, в том числе как PID 1 контейнера. Он завершает текущую итерацию с принятым заданием, затем выходит с освобождением lifetime lock; idle ожидание прерывается сразу. Compose даёт до 60 секунд на штатную остановку. Это не доказательство завершения remote effect: если процесс всё же убит или reply потерян, действует прежнее восстановление с `UNKNOWN_OUTCOME`, без автоматического повтора.

## UID и SQLite

API и Worker имеют разные UID и общую отдельную группу `ho-app-db`. Shared Store требует точного владельца API, GID этой группы, directory mode 2770 и database mode 0660. Setgid сохраняет группу WAL/SHM и Worker lock. Runtime configuration задаёт эти значения явно. Приватный режим разработки с mode 0700/0600 остаётся доступен.

Vault и Broker receipts принадлежат `ho-broker` в отдельных каталогах 0700. Gate journal и signing key принадлежат root в каталоге 0700. Backend не имеет групп Broker/gate и не получает их sockets. Worker имеет только нужные supplementary groups и не читает Vault, DEK или gate database. AF_UNIX server проверяет UID/GID из SO_PEERCRED; JSON не задаёт роль. Systemd создаёт listener до запуска сервисного UID, поэтому клиент допускает доверенный root socket activation и ожидаемый UID службы.

Новая БД имеет schema 2. Schema 1 сохраняет Auth API, но очередь отвечает `QUEUE_SCHEMA_REQUIRES_VERIFIED_MIGRATION`. Автоматической миграции или удаления существующих пользователей нет. Перенос существующей БД должен пройти отдельный подтверждённый Backup Gate; он не заменяется копированием WAL/SHM.

## Vault и SSH

Private key versions неизменяемы. Blob зашифрован XChaCha20-Poly1305; AAD включает secret/version, kind, purpose, owner, consumer digest, target, state, policy revision и key version. Metadata и состояние находятся в private Broker journal. Замена metadata или ciphertext не даёт разрешённого использования. `REVOKED` запрещает следующий Use.

Broker получает runtime DEK из OS credential. В systemd профиле root-owned source имеет mode 0600, `LoadCredential` предоставляет приватную копию только Broker. Инициализация Vault использует уже подготовленный credential, а не создаёт новый ключ при утрате данных. Offline Owner age identity этому коду не передаётся.

AsyncSSH принимает Ed25519 key непосредственно в памяти Broker. Agent, password auth, keyboard-interactive auth и внешняя SSH config отключены. Цель — только защищённый numeric IP из заданного CIDR и порта; loopback, link-local, metadata endpoints, IPv6 zones и непредусмотренные capabilities отклоняются. Хост проверяется по закреплённому Ed25519 key. Общая длительность соединения ограничена; каждый поток ограничен 2048 байтами. При ошибке остаётся фиксированный код, а произвольный вывод не попадает в SQLite, SSE или ошибку API.

На managed Ubuntu устанавливаются root-owned `remote/ssh-gateway` и `remote/typed-helper` по фиксированным путям из §31.2. Gateway принимает только `hostorbit.v1.probe` и точный JSON. Helper не принимает argv и выполняет только наблюдение. Account `hostorbit-svc` использует `/bin/sh`, server-side ForceCommand, точный sudoers без аргументов, root-owned authorized_keys и запрет PTY/forwarding/environment override. Первичный fingerprint подтверждается отдельно владельцем.

## Профили запуска и стенд

`deploy/sysusers.d`, `deploy/tmpfiles.d` и `deploy/systemd` описывают пользователей, права каталогов, socket activation и sandboxing. `deploy/runtime.example.json` содержит пример числовых UID/GID; при установке их сверяют с фактическими созданными accounts. Runtime JSON принадлежит root и закрыт от записи группой. Target policy устанавливается отдельно владельцем и не изменяется регистрацией через Web API.

Локальные команды `hostorbit-runtime initialize-supervisor`, `initialize-broker`, `import-key` и `register-observations` выполняются только ожидаемым OS пользователем. Инициализация отдельная и отказывается заменять существующие journals/key versions. Для Broker init/import требуется тот же защищённый OS credential, что и для сервиса. `register-observations` — root-side импорт защищённого summary в application registry. Сервисы не выполняют эту инициализацию при каждом запуске.

[Development-установщик](stage1-installation.md) уже проверен на чистой Ubuntu 24.04: подписанный bundle, настоящие systemd services, Compose namespaces, локальный Owner, HTTPS proxy и restart. Он требует подготовленные Docker/Python и не меняет DNS, system Nginx или чужие контейнеры. [Репетиция схемы 1 → 2](stage1-migrations.md) проверяет отдельную копию; применение к рабочей БД остаётся закрытым до полного maintenance/backup/TimeHealth workflow.

Локально запускаются `python -m unittest discover -s tests_app` и `python -m unittest discover -s tests_runtime`. Контракты in-process не подменяют kernel boundary. Отдельный disposable GitHub-hosted VM job запускает реальные API/Worker/Broker под разными UID, root authority и SSH server в отдельном network namespace. Он проверяет DAC/SO_PEERCRED, совместную запись SQLite, replay и подмену подписи, raw-output canary, host-key mismatch, второй Worker и потерю первого Worker при работающем Broker. Стенд использует один kernel и не удостоверяет независимый физический DR.
