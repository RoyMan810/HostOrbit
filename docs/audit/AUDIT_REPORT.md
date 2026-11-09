# Независимый технический аудит HostOrbit

## Резюме и границы

- Проверенная база: `main` / `034ed1d6ffe7ad4e7101596c08c2aca2d0b81382`, сверена с `origin/main` через fetch. Документы написаны в отдельной ветке; незакоммиченные настройки пользователя не входят в аудитируемый commit.
- ТЗ: `/home/roman/Downloads/HostOrbit_Technical_Spec_v2.3.docx`, SHA-256 `d7f4e31e8ae20ae4c1da47d8e3fbe8cb45a450feefa5bf409c7104cf125ca0ad`. Это **входная**, а не итоговая редакция DOCX из [журнала приёмки](../../evidence/acceptance/stage0-2026-11-07/baseline-execution-update.json): итоговый DOCX имеет другой SHA-256. Извлечённые из DOCX все 71 строка индекса требований совпали с реестром по ID, release/stage, owner и списку AC; архитектурный каркас, границы безопасности, релизные gates, требования к нагрузке и восстановлению также изучены. Полное построчное сопоставление текста ТЗ и кода не выполнено. Markdown, необходимого для штатного `stage0.baseline`, в распоряжении аудита нет.
- Реестр: [снимок 71 требования и 84 AC](../../evidence/acceptance/stage0-2026-11-07/HostOrbit_Requirements_Registry_v2.3.json). Статусы реестра — исторические, а не результаты этого аудита.
- Целевая нагрузка по §13/§37 ТЗ: до 25 VPS и 200 сервисных объектов на 2 vCPU / 4 GiB RAM / 40 GiB SSD; для capacity требуется 30-дневный набор и восьмичасовой смешанный soak. Такой стенд здесь не выполнялся.
- Вердикт: **не production**. Продолжать Stage2 на нынешнем каркасе можно, сохраняя запрет mutations; до включения изменений инфраструктуры закрыть доказательные, backup/recovery и нагрузочные gates. Переписывать систему или вводить дополнительные сервисы без измерений оснований нет.

## Подсистемы и охват

| Область | Проверено в коде/артефактах | Ограничения |
|---|---|---|
| API/Auth/RBAC/сессии | [api.py](../../hostorbit/api.py), [auth.py](../../hostorbit/auth.py), [queue.py](../../hostorbit/queue.py), [inventory.py](../../hostorbit/inventory.py), тесты API | Не проведён исчерпывающий adversarial pentest |
| SQLite/Audit/Outbox | [database.py](../../hostorbit/database.py), схема и select inventory, gate и релевантные тесты | Длительный concurrency/ENOSPC soak не проводился |
| Worker/Broker/Gate/SSH | [worker.py](../../hostorbit/worker.py), [authority.py](../../hostorbit/runtime/authority.py), [ipc.py](../../hostorbit/runtime/ipc.py), [ssh.py](../../hostorbit/runtime/ssh.py); границы и unit-тесты | Реальные UID/systemd/SSH в этом аудите не воспроизводились |
| Backup/Rescue | [controller_backup.py](../../hostorbit/runtime/controller_backup.py), [archive_stream.py](../../hostorbit/runtime/archive_stream.py), [rescue.py](../../hostorbit/runtime/rescue.py), [recovery_import.py](../../hostorbit/runtime/recovery_import.py), ограничения и unit-тесты | Независимый DR и реальный SFTP не запускались |
| Frontend | Компоненты inventory/probe/audit, сборка и 18 браузерных сценариев | Полного ручного accessibility- и кроссбраузерного аудита нет |
| Stage0, документация, CI, зависимости | Реестр/gates, [checks.yml](../../.github/workflows/checks.yml), исторические evidence, список PR и inline-комментарии; перечень файлов Git | Все 231 файла не прочитаны построчно; ранние реализации и все обсуждения review не проверены полностью |

Таким образом, это документированный **частичный независимый аудит**, а не свидетельство полного анализа всего репозитория. Реестр ниже охватывает все идентификаторы, но не заменяет независимую проверку реализации каждого требования.

## Подтверждённые замечания

Доказанного P0 в проверенных путях не установлено; непроверенные области не позволяют заключить, что P0 отсутствуют во всём проекте. Для AUD-03 подтверждён пропуск проверки, а включение untracked-модуля в wheel остаётся гипотезой; AUD-05 — подтверждённое несоответствие лимитов с расчётным, не сетевым, сценарием.

### AUD-01 — P1: у текущего main не проходит Stage1 evidence gate

- **Компонент и места:** [checks.yml:203–208](../../.github/workflows/checks.yml#L203-L208), [requirements.py:271–306](../../stage0/requirements.py#L271-L306).
- **Доказательство:** в чистой копии указанного commit `--gate Stage1` вернул 2: несовпадение исходников/артефактов в `owner_auth`, `rbac`, `sqlite_audit_outbox`, `ssh_helper`, `broker_ipc`. Например, в отчётах совпадение нарушено для `hostorbit/inventory.py`; в owner_auth также для `api.py` и `auth.py`. `admission_supervisor` совпал. Последний [HostOrbit CI](https://github.com/RoyMan810/HostOrbit/actions/runs/42717373925) для этого SHA завершился failure, job Stage0 prototypes — failure. Причину конкретного удалённого job по его логу независимо не подтверждали; локальный gate воспроизведён.
- **Влияние:** текущая ревизия не проходит обязательную автоматическую проверку; историческую приёмку Stage1 это само по себе не отменяет.
- **Исправление:** повторить релевантные unit и реальные boundary-проверки на новом зафиксированном SHA; выпустить новые свидетельства, не переписывая историю и не подменяя хеши без испытаний.
- **Риск исправления:** формальная замена digest без повторного теста создаст ложное доказательство.
- **Проверка:** обе команды Stage0/Stage1 gate и полный обязательный CI на конкретном SHA должны пройти с новыми доказательствами.

### AUD-02 — P1: можно создать архив Controller, который штатный Rescue не принимает

- **Компонент и места:** [controller_backup.py:204–221](../../hostorbit/runtime/controller_backup.py#L204-L221), [controller_backup.py:304–317](../../hostorbit/runtime/controller_backup.py#L304-L317), [rescue.py:83–89](../../hostorbit/runtime/rescue.py#L83-L89), [rescue_payload.py:26](../../hostorbit/runtime/rescue_payload.py#L26).
- **Доказательство:** backup ограничивает каждую из четырёх баз 512 MiB, но не ограничивает общий архив пределом Rescue; provenance допускает ciphertext до 4 GiB. Rescue отказывает любому ciphertext больше 512 MiB, а также plaintext payload больше этого предела. На изолированном файле размером 536 870 913 байт `ciphertext_stream` вернул `RESCUE_CIPHERTEXT_SIZE_UNSUPPORTED`. Сам многосотмегабайтный подписанный архив end-to-end здесь не строился.
- **Влияние:** допустимые накопленные данные могут дать `LOCAL_SIGNED_ONLY` архив, который штатной процедурой не восстановить. Система явно не называет его restore-verified, но оператор может остаться без применимой копии.
- **Исправление:** до признания архива пригодным обеспечить единый проверяемый лимит полного payload и ciphertext с учётом tar/age overhead; при превышении безопасно отказывать с понятным кодом. Для большего масштаба отдельно спроектировать потоковое восстановление без plaintext на диске.
- **Риск исправления:** слишком консервативная оценка заблокирует часть допустимых backup; расширение лимита затронет RAM и секреты.
- **Проверка:** интеграционный round-trip непосредственно ниже/выше обоих пределов, несколько больших БД и файлов Vault, ENOSPC; невозможный к восстановлению результат не должен объявляться пригодным.

### AUD-03 — P1: подписывается не полностью воспроизводимый исходный состав

- **Компонент и места:** [build_bundle.py:38–47](../../deploy/build_bundle.py#L38-L47), [build_bundle.py:54–63](../../deploy/build_bundle.py#L54-L63), [pyproject.toml:19–20](../../pyproject.toml#L19-L20).
- **Доказательство:** проверка чистоты использует `--untracked-files=no`, а wheel строится из рабочего каталога. В изолированном git clone добавленный `hostorbit/audit_untracked_fixture.py` не отображался этой проверкой. Само включение файла в wheel в данной среде не воспроизведено: отсутствуют pip/setuptools и Python 3.13; это **подтверждённый пропуск проверки, а фактическое включение — гипотеза до теста**. Также upstream wheels скачиваются по версии, а хеши вычисляются только после скачивания: подпись защищает полученные байты, но не доказывает их соответствие заранее проверенному набору.
- **Влияние:** риск подписать артефакт, который нельзя однозначно связать с утверждённым commit или заранее доверенными зависимостями; это не доказательство компрометации.
- **Исправление:** строить из чистого экспортированного commit и проверять заранее закреплённые хеши wheels до подписи.
- **Риск исправления:** потребуются обновление release-процедуры и всех закреплённых платформенных wheels.
- **Проверка:** на Python 3.13 добавить неотслеживаемый модуль и убедиться, что он отсутствует в wheel; подменённый wheel должен отклоняться до подписи.

### AUD-04 — P2: после Rescue история карантинного задания возвращает ошибку

- **Компонент и места:** [recovery_import.py:258–266](../../hostorbit/runtime/recovery_import.py#L258-L266), [queue.py:114–149](../../hostorbit/queue.py#L114-L149).
- **Доказательство:** импорт изменяет незавершённый Job на `CANCELLED_SAFE`/`UNKNOWN_OUTCOME` с `RESTORE_QUARANTINE`, но не добавляет `job.finished` и не увеличивает revision. В изолированной копии применён тот же UPDATE: `GET /jobs/{id}` ответил 200 / `CANCELLED_SAFE`, а `/timeline` — 503 / `JOB_TIMELINE_INVALID`.
- **Влияние:** после восстановления оператор не может получить согласованную историю затронутого задания.
- **Исправление:** в одной транзакции карантина добавлять корректное терминальное событие и revision, сохраняя старые события; отдельно определить обратную совместимость уже созданных восстановлений.
- **Риск исправления:** изменение формата/истории восстановления и инвариантов Audit; нельзя подделать уже существовавший исход.
- **Проверка:** полноценный Rescue round-trip для `QUEUED` и после dispatch, валидная Timeline и проверка цепочки Audit после рестарта.

### AUD-05 — P2: предел времени SFTP не согласован с допустимым размером

- **Компонент и места:** [sftp_publication.py:39–68](../../hostorbit/runtime/sftp_publication.py#L39-L68), [sftp_publication.py:146–148](../../hostorbit/runtime/sftp_publication.py#L146-L148), [publication.py:25](../../hostorbit/runtime/publication.py#L25).
- **Доказательство:** каждая публикация передаёт файл и полностью читает его обратно, но весь сеанс ограничен 120 секундами, хотя transport допускает архивы до 4 GiB. Например, при 10 Мбит/с только передача и чтение 300 MiB занимают порядка 8 минут; реальный сетевой тест в данном аудите не запускался.
- **Влияние:** корректный SFTP и целый архив могут постоянно давать timeout; remote partial остаётся на сервере по текущему контракту.
- **Исправление:** согласовать допустимые размер, скорость и deadline; задать ограниченный общий deadline по размеру с проверкой прогресса, не разрешая бесконечное зависание.
- **Риск исправления:** увеличение длительности процесса и удержания credential/session; сохранить checkpoint и revoke-проверки.
- **Проверка:** ограниченная полоса и fault injection, проверка timeout, отмены, повторной публикации и отсутствия ложного успеха.

### AUD-06 — P2: растущая история замедляет каждую страницу инвентаря

- **Компонент и места:** [inventory.py:13–34](../../hostorbit/inventory.py#L13-L34), [database.py:56–70](../../hostorbit/database.py#L56-L70).
- **Доказательство:** `EXPLAIN QUERY PLAN` на текущей схеме показывает для обоих коррелированных подзапросов поиск по `audit_target_time` и `USE TEMP B-TREE FOR ORDER BY`. Это происходит для каждого ресурса; время и точка отказа на нормативном dataset не измерялись.
- **Влияние:** стоимость чтения растёт вместе с историей; страница до 100 записей не ограничивает работу по истории. Ограничение уже отражено в [документации Stage2](../stage2-inventory.md).
- **Исправление:** сначала измерить нормативный soak; затем добавить минимальный индекс для `(target_id,event,seq)` через проверенную миграцию либо иной обоснованный запрос.
- **Риск исправления:** блокировка/рост БД при миграции и несовместимость старого Rescue.
- **Проверка:** план запроса и p95 на датасете §37, миграция/restore исторических схем.

## Фактические проверки

Изолированный `git archive` текущего SHA; Linux, Python 3.14.4 / SQLite 3.46.1, Node 24.22.1. Это **не** нормативный Python 3.13; подписанный age v1.3.2 скачан по проектному маршруту с проверкой SHA-256. Первые попытки без age закончились ошибками, затем повторены:

| Проверка | Результат |
|---|---|
| Stage0 `tests/` | 73/73 прошли с age |
| `tests_app/` | 75/75 прошли |
| `tests_runtime/` | 157/157 прошли с age |
| `tests_tools/` | 17/17 прошли |
| Ruff и `tools/check_repository.py` | прошли |
| Web TypeScript/Vite | сборка прошла |
| Playwright/Chromium | 18/18 прошли после установки браузера во временный каталог; первые попытки не стартовали из-за Python/браузера |
| Stage0 gate | exit 0 |
| Stage1 gate | exit 2, пять capability digest mismatches (AUD-01) |
| Stage2 / Stage3 gates | exit 2; Stage2: AC-28 и AC-B05 NOT_RUN; Stage3: 61 blocker |

Реальные SSH/systemd/Docker и независимый off-host DR здесь не запускались. Их прошлые зелёные CI jobs — историческое свидетельство конкретного SHA и среды, не результаты этого локального аудита.

## GitHub и документация

GitHub API: 52 PR, все закрыты и объединены; отдельных Issues и открытых PR на момент запроса не найдено, публичная ветка одна (`main`). Получено девять inline review-комментариев, все автоматические замечания о связности; показатель связности не доказывает дефект. Проверены списки review 51 из 52 PR; для #48 достигнут лимит GitHub API, разрешённость отдельных review threads не подтверждена. [ADR AC-28](../adr/0001-registry-ac28-stage.md) согласует Stage2; входной DOCX не совпадает с обновлённой после приёмки бинарной редакцией по хешу, поэтому полная проверка синхронности экспортов остаётся открытой.

## Предварительные оценки

Шкала: 10 — готово и независимо доказано на целевом профиле; 5 — работающий ограниченный прототип с существенными открытыми gates; 0 — нет полезной реализации/доказательств. Это экспертные оценки **проверенного поднабора**, не измерения всего проекта.

| Направление | /10 | Обоснование и границы |
|---|---:|---|
| Архитектура | 6 | Границы Gate/Broker и single-active соответствуют модели, но контракты восстановления не согласованы (AUD-02/04); будущие mutation flows не доказаны. |
| Безопасность | 6 | Scoped RBAC, pinning и изоляция есть; Backend остаётся TCB, независимый pentest и обновлённые evidence не завершены. |
| Backend | 6 | 75 app и 157 runtime tests прошли; recovery/timeline дефект и release-input риск остаются. |
| Frontend | 6 | 18 Chromium-сценариев и сборка прошли, интерфейс ограничен Stage2; полный accessibility и другие браузеры не проверены. |
| Надёжность | 4 | Явный UNKNOWN и fail-closed пути есть; mismatch архивов и неподтверждённый независимый DR ограничивают доверие. |
| Производительность | 4 | План инвентаря показывает сортировку истории; целевой soak не выполнен, поэтому оценка предварительная. |
| Тестирование | 6 | 322 Python и 18 браузерных проверок прошли, но локально не выполнены native, полный DR и capacity; Stage1 gate не прошёл. |
| DevOps / CI/CD | 5 | Есть подписанные bundles, pinned Actions и реальные CI jobs; последний общий CI failure, AUD-01/03. |
| Поддерживаемость | 5 | Документированы границы и история; несколько автономных журналов и контрактов требуют синхронизации. Полный аудит кода не завершён. |
| Готовность к production | 2 | Stage2/3 gates не пройдены, нет новых независимых capacity/DR доказательств; production mutations выключены. |

## Матрица требований

Для проверенных областей сопоставление с реальными тестами: FR-001/002/003 → [test_auth_api.py](../../tests_app/test_auth_api.py), [test_permissions.py](../../tests_app/test_permissions.py), [test_http_boundary.py](../../tests_app/test_http_boundary.py); FR-006/008 → [test_inventory_api.py](../../tests_app/test_inventory_api.py); FR-013 → [test_queue_api.py](../../tests_app/test_queue_api.py), [test_worker_broker.py](../../tests_runtime/test_worker_broker.py); FR-015/024 → [test_controller_backup.py](../../tests_runtime/test_controller_backup.py), [test_rescue.py](../../tests_runtime/test_rescue.py), [test_recovery_install.py](../../tests_runtime/test_recovery_install.py); CTRL-B01…B10 → исторические [evidence/tests](../../evidence/tests/). Эти файлы содержат частичные проверки, а не обязательно полные AC. Для остальных строк тесты независимо не сопоставлены.

Ниже — полный перечень ID из снимка реестра. `AC` и `evidence` — ссылки, **заявленные реестром**, не подтверждение текущего PASS. `Реализация` дана только там, где аудит выявил релевантный код; `не установлена` не означает автоматически отсутствия реализации. Все статусы требований в снимке — `NOT_RUN`; отдельные 15 Stage0 AC имеют исторический PASS. Это инвентаризация для дальнейшей проверки, а не завершённая проверка соответствия каждого требования.

| Требование и этап | Релевантный компонент; полнота не установлена | Связанные AC в реестре | Evidence, указанный реестром | Статус требования в снимке |
|---|---|---|---|---|
| FR-001.1 / Stage1 | [auth.py](../../hostorbit/auth.py) | AC-01 | `evidence/owner_bootstrap_auth.json` — нет в дереве | NOT_RUN |
| FR-002.1 / Stage1 | [auth.py](../../hostorbit/auth.py) | AC-01, AC-42, AC-A04 | `evidence/sessions_csrf_rate_limits.json` — нет в дереве | NOT_RUN |
| FR-003.1 / Stage1 | [auth.py](../../hostorbit/auth.py) | AC-02, AC-06, AC-A04, AC-A18 | `evidence/rbac_scopes_negative.json` — нет в дереве | NOT_RUN |
| FR-004.1 / Stage2 | [../web/src/main.tsx](../../web/src/main.tsx) | AC-26 | `evidence/ru_en_a11y.json` — нет в дереве | NOT_RUN |
| FR-005.1 / Stage1 | [runtime/ssh.py](../../hostorbit/runtime/ssh.py) | AC-03, AC-28, AC-33, AC-A07, AC-A18 | `evidence/ssh_bootstrap_capability.json` — нет в дереве | NOT_RUN |
| FR-006.1 / Stage2 | [inventory.py](../../hostorbit/inventory.py) | AC-05, AC-15, AC-28, AC-33 | `evidence/inventory_discovery.json` — нет в дереве | NOT_RUN |
| FR-007.1 / Stage2 | [runtime/ssh.py](../../hostorbit/runtime/ssh.py) | AC-05, AC-28, AC-33, AC-A07 | `evidence/adapter_mvp_capabilities.json` — нет в дереве | NOT_RUN |
| FR-007.2 / Stage4 | не установлена | AC-25 | `evidence/remnawave_contract.json` — нет в дереве | NOT_RUN |
| FR-008.1 / Stage2 | [inventory.py](../../hostorbit/inventory.py) | AC-07, AC-09, AC-28, AC-A05, AC-A17 | `evidence/service_restart_scoped.json` — нет в дереве | NOT_RUN |
| FR-008.2 / Stage4 | не установлена | AC-18, AC-23 | `evidence/infrastructure_update.json` — нет в дереве | NOT_RUN |
| FR-009.1 / Stage4 | не установлена | AC-25 | `evidence/vpn_topology_manual_exit.json` — нет в дереве | NOT_RUN |
| FR-010.1 / Stage2 | не установлена | AC-15, AC-17, AC-33, AC-A18 | `evidence/ports_readonly.json` — нет в дереве | NOT_RUN |
| FR-011.1 / Stage2 | не установлена | AC-05, AC-17, AC-34, AC-A08, AC-A16, AC-43 | `evidence/nginx_isolated_publication.json` — нет в дереве | NOT_RUN |
| FR-011.2 / Stage4 | не установлена | AC-24 | `evidence/domain_tls_manage.json` — нет в дереве | NOT_RUN |
| FR-012.1 / Stage1 | не установлена | AC-16, AC-49 | `evidence/firewall_ssh_denied.json` — нет в дереве | NOT_RUN |
| FR-012.2 / Stage4 | не установлена | AC-16 | `evidence/safe_apply_watchdog.json` — нет в дереве | NOT_RUN |
| FR-013.1 / Stage1 | [queue.py](../../hostorbit/queue.py) | AC-06, AC-07, AC-08, AC-09, AC-37, AC-52, AC-A05, AC-A08, AC-A09, AC-A10, AC-A19, AC-48 | `evidence/durable_job_reconcile.json` — нет в дереве | NOT_RUN |
| FR-014.1 / Stage2 | [migrations.py](../../hostorbit/migrations.py) | AC-06, AC-36, AC-A08 | `evidence/etag_diff_preflight.json` — нет в дереве | NOT_RUN |
| FR-014.2 / Stage4 | не установлена | AC-06 | `evidence/advanced_editor.json` — нет в дереве | NOT_RUN |
| FR-015.1 / Stage2 | [runtime/controller_backup.py](../../hostorbit/runtime/controller_backup.py) | AC-11, AC-12, AC-38, AC-47, AC-A02, AC-A03, AC-A11, AC-A12, AC-A13 | `evidence/controller_resource_backup.json` — нет в дереве | NOT_RUN |
| FR-016.1 / Stage2 | [database.py](../../hostorbit/database.py) | AC-10, AC-45, AC-A10, AC-A17 | `evidence/audit_outbox_redaction.json` — нет в дереве | NOT_RUN |
| FR-016.2 / Stage4 | не установлена | AC-27, AC-31 | `evidence/audit_remote_archive.json` — нет в дереве | NOT_RUN |
| FR-017.1 / Stage1 | [runtime/vault.py](../../hostorbit/runtime/vault.py) | AC-04, AC-12, AC-35, AC-38, AC-47, AC-A02, AC-A04, AC-A14 | `evidence/secrets_acl_vault.json` — нет в дереве | NOT_RUN |
| FR-018.1 / Stage2 | [../web/src/main.tsx](../../web/src/main.tsx) | AC-15, AC-26, AC-28, AC-49 | `evidence/dashboard_service_readonly.json` — нет в дереве | NOT_RUN |
| FR-018.2 / Stage4 | не установлена | AC-19, AC-20, AC-30, AC-31 | `evidence/advanced_centers.json` — нет в дереве | NOT_RUN |
| FR-019.1 / Stage4 | не установлена | AC-20 | `evidence/templates_versioning.json` — нет в дереве | NOT_RUN |
| FR-020.1 / Stage4 | не установлена | AC-19 | `evidence/groups_frozen_targets.json` — нет в дереве | NOT_RUN |
| FR-021.1 / Stage1 | [auth.py](../../hostorbit/auth.py) | AC-02, AC-06 | `evidence/policy_rbac_basic.json` — нет в дереве | NOT_RUN |
| FR-021.2 / Stage4 | не установлена | AC-20 | `evidence/policy_inheritance_ui.json` — нет в дереве | NOT_RUN |
| FR-022.1 / Stage1 | [runtime/authority.py](../../hostorbit/runtime/authority.py) | AC-18, AC-39, AC-50, AC-A15 | `evidence/host_updater_release.json` — нет в дереве | NOT_RUN |
| FR-022.2 / Stage4 | не установлена | AC-18, AC-23 | `evidence/infra_updates.json` — нет в дереве | NOT_RUN |
| FR-023.1 / Stage1 | [runtime/recovery_import.py](../../hostorbit/runtime/recovery_import.py) | AC-14, AC-22 | `evidence/scheduler_paused_recovery.json` — нет в дереве | NOT_RUN |
| FR-023.2 / Stage5 | не установлена | AC-22 | `evidence/scheduler_calendar_approvals.json` — нет в дереве | NOT_RUN |
| FR-024.1 / Stage1 | [runtime/rescue.py](../../hostorbit/runtime/rescue.py) | AC-12, AC-13, AC-14, AC-38, AC-40, AC-41, AC-46, AC-47, AC-51, AC-A01, AC-A02, AC-A05, AC-A06, AC-44, AC-A21 | `evidence/manual_recovery_quarantine.json` — нет в дереве | NOT_RUN |
| FR-024.2 / Stage4 | не установлена | AC-13 | `evidence/migration_web_wizard.json` — нет в дереве | NOT_RUN |
| FR-025.1 / Stage2 | [runtime/controller_backup.py](../../hostorbit/runtime/controller_backup.py) | AC-11, AC-21 | `evidence/protected_retention.json` — нет в дереве | NOT_RUN |
| FR-025.2 / Stage4 | не установлена | AC-21 | `evidence/storage_cleanup_ui.json` — нет в дереве | NOT_RUN |
| FR-026.1 / Stage2 | [runtime/cli.py](../../hostorbit/runtime/cli.py) | AC-01, AC-03, AC-28 | `evidence/onboarding_entry.json` — нет в дереве | NOT_RUN |
| FR-027.1 / Stage2 | [../web/src/audit.tsx](../../web/src/audit.tsx) | AC-29 | `evidence/in_app_notifications.json` — нет в дереве | NOT_RUN |
| FR-027.2 / Stage4 | не установлена | AC-29 | `evidence/telegram_delivery.json` — нет в дереве | NOT_RUN |
| FR-028.1 / Stage5 | не установлена | AC-30 | `evidence/search_rbac_palette.json` — нет в дереве | NOT_RUN |
| FR-029.1 / Stage1 | [../docs/README.md](../../docs/README.md) | AC-32, AC-47 | `evidence/offline_help_recovery.json` — нет в дереве | NOT_RUN |
| FR-029.2 / Stage4 | не установлена | AC-32 | `evidence/help_center_updates.json` — нет в дереве | NOT_RUN |
| FR-030.1 / Stage1 | [runtime/ssh.py](../../hostorbit/runtime/ssh.py) | AC-04, AC-45, AC-A17 | `evidence/redaction_canary.json` — нет в дереве | NOT_RUN |
| FR-030.2 / Stage4 | не установлена | AC-31 | `evidence/privacy_review_bundle.json` — нет в дереве | NOT_RUN |
| FR-031.1 / Stage2 | [../web/src/main.tsx](../../web/src/main.tsx) | AC-26 | `evidence/themes_ru_en_timezone.json` — нет в дереве | NOT_RUN |
| FR-031.2 / Stage5 | не установлена | AC-26 | `evidence/advanced_appearance.json` — нет в дереве | NOT_RUN |
| FR-032.1 / Stage2 | [inventory.py](../../hostorbit/inventory.py) | AC-05, AC-15, AC-28, AC-A16 | `evidence/service_details_mvp.json` — нет в дереве | NOT_RUN |
| FR-032.2 / Stage4 | не установлена | AC-20, AC-23 | `evidence/service_catalog_post.json` — нет в дереве | NOT_RUN |
| NFR-01 / Stage1 | [api.py](../../hostorbit/api.py) | AC-01, AC-02, AC-04, AC-B10 | `evidence/nfr_nfr-01.json` — нет в дереве | NOT_RUN |
| NFR-02 / Stage1 | [worker.py](../../hostorbit/worker.py) | AC-07, AC-08, AC-A10, AC-B01, AC-B09 | `evidence/nfr_nfr-02.json` — нет в дереве | NOT_RUN |
| NFR-03 / Stage2 | [runtime/rescue.py](../../hostorbit/runtime/rescue.py) | AC-11, AC-12, AC-A03, AC-B02, AC-B03 | `evidence/nfr_nfr-03.json` — нет в дереве | NOT_RUN |
| NFR-04 / Stage2 | [inventory.py](../../hostorbit/inventory.py) | AC-15, AC-28 | `evidence/nfr_nfr-04.json` — нет в дереве | NOT_RUN |
| NFR-05 / Stage2 | [../web/src/main.tsx](../../web/src/main.tsx) | AC-26, AC-B06 | `evidence/nfr_nfr-05.json` — нет в дереве | NOT_RUN |
| NFR-06 / Stage2 | [runtime/authority.py](../../hostorbit/runtime/authority.py) | AC-18, AC-A15, AC-B09 | `evidence/nfr_nfr-06.json` — нет в дереве | NOT_RUN |
| NFR-07 / Stage1 | [../stage0/requirements.py](../../stage0/requirements.py) | AC-A20, AC-B06, AC-B07 | `evidence/nfr_nfr-07.json` — нет в дереве | NOT_RUN |
| NFR-08 / Stage2 | [runtime/controller_backup.py](../../hostorbit/runtime/controller_backup.py) | AC-A22, AC-B02 | `evidence/nfr_nfr-08.json` — нет в дереве | NOT_RUN |
| P0-1 / Stage0 | [runtime/activation.py](../../hostorbit/runtime/activation.py) | AC-13, AC-40, AC-46, AC-A01, AC-A05, AC-B04 | `evidence/p0-1.json` — нет в дереве | NOT_RUN |
| P0-2 / Stage0 | [runtime/rescue.py](../../hostorbit/runtime/rescue.py) | AC-11, AC-12, AC-A02, AC-A03, AC-B02, AC-B03 | `evidence/p0-2.json` — нет в дереве | NOT_RUN |
| P0-3 / Stage0 | [runtime/policy.py](../../hostorbit/runtime/policy.py) | AC-05, AC-A08, AC-A16 | `evidence/p0-3.json` — нет в дереве | NOT_RUN |
| P0-4 / Stage0 | [queue.py](../../hostorbit/queue.py) | AC-07, AC-08, AC-A10, AC-A19, AC-B01, AC-B09 | `evidence/p0-4.json` — нет в дереве | NOT_RUN |
| CTRL-B01 / Stage0 | [../tests/lab/docker_late_effect.py](../../tests/lab/docker_late_effect.py) | AC-B01 | `evidence/b01_test.json` — нет в дереве | NOT_RUN |
| CTRL-B02 / Stage0 | [../stage0/snapshot.py](../../stage0/snapshot.py) | AC-B02 | `evidence/b02_test.json` — нет в дереве | NOT_RUN |
| CTRL-B03 / Stage0 | [../stage0/recovery.py](../../stage0/recovery.py) | AC-B03 | `evidence/b03_test.json` — нет в дереве | NOT_RUN |
| CTRL-B04 / Stage0 | [../stage0/admission.py](../../stage0/admission.py) | AC-B04 | `evidence/b04_test.json` — нет в дереве | NOT_RUN |
| CTRL-B05 / Stage2 | [runtime/resource_archive.py](../../hostorbit/runtime/resource_archive.py) | AC-B05 | `evidence/b05_test.json` — нет в дереве | NOT_RUN |
| CTRL-B06 / Stage0 | [../stage0/sessions.py](../../stage0/sessions.py) | AC-B06 | `evidence/b06_test.json` — нет в дереве | NOT_RUN |
| CTRL-B07 / Stage0 | [../stage0/baseline.py](../../stage0/baseline.py) | AC-B07 | `evidence/b07_test.json` — нет в дереве | NOT_RUN |
| CTRL-B08 / Stage0 | [runtime/ssh.py](../../hostorbit/runtime/ssh.py) | AC-B08 | `evidence/b08_test.json` — нет в дереве | NOT_RUN |
| CTRL-B09 / Stage0 | [runtime/authority.py](../../hostorbit/runtime/authority.py) | AC-B09 | `evidence/b09_test.json` — нет в дереве | NOT_RUN |
| CTRL-B10 / Stage0 | [runtime/ipc.py](../../hostorbit/runtime/ipc.py) | AC-B10 | `evidence/b10_test.json` — нет в дереве | NOT_RUN |
