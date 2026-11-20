# Проверка миграции Foundation БД

[Документация](README.md) · [Требования v2.4](spec/HostOrbit_Technical_Spec_v2.4.md)

Команда `migration-rehearsal` проверяет переход исторической схемы 1 в схему 2 **на отдельных приватных копиях**. Рабочая БД открывается SQLite в `mode=ro` с `query_only=ON`. Одна read transaction закрепляет согласованную WAL-точку для обеих копий через SQLite Online Backup API. Записи обычного приложения могут продолжаться; отчёт относится к закреплённой точке, а не обещает отсутствие последующих записей.

Пример для root-консоли с установленным host runtime:

```bash
sudo /opt/hostorbit/venv/bin/hostorbit \
  --database /var/lib/hostorbit/app/controller.sqlite3 \
  --database-owner "$(id -u ho-api)" --database-group "$(getent group ho-app-db | cut -d: -f3)" \
  migration-rehearsal --output /var/tmp/hostorbit-migration-review-001
```

Каталог вывода должен быть новым; существующий каталог или symlink не заменяется. Родители должны быть доверенными и недоступными для чужой записи; корневой sticky `/var/tmp` допустим. Вывод получает mode `0700`, файлы `0600`. Копии содержат password hashes и server-side sessions, поэтому сохраняются только для локального root review. Это не зашифрованный ControllerBackup и не off-host копия.

Исторический `schema_v1.sql` взят из коммита `f23e066ecab184d1f3f731917b78a382b3f59179` и дополнительно закреплён SHA-256 внутри пакета. Проверяется весь набор таблиц, индексов и триггеров, `integrity_check`, foreign keys и Audit/Outbox chain. Одного `user_version=1` недостаточно; дополнительная таблица, отсутствующее ограничение, повреждённый аудит или неизвестная схема запрещают продолжение. Свежая установка уже создаёт схему 3.

Миграция копии создаёт таблицы очереди, добавляет событие `database.schema_migrated` с признаком `rehearsal` и меняет `user_version` в **одной транзакции**. SQL выполняется по statement, без `executescript`, который мог бы неявно завершить открытую транзакцию. Сравнивается дайджест всех исходных строк: пользователи, password hashes, роли, grants, сессии, лимиты, bootstrap, reauth и исходный Audit/Outbox должны сохраниться. Новые таблицы остаются пустыми. После commit копия открывается заново и проверяется повторно.

Файлы `source.sqlite3` и `migrated.sqlite3` остаются в каталоге review. `rehearsal.json` содержит только состояния, количество строк и дайджесты, без содержимого credentials. Успех — только `REHEARSAL_PASSED`. Ошибка даёт `FAILED`; `RUNNING` после kill/reboot также не означает успех. Бюджет репетиции — 30 секунд с monotonic clock и SQLite progress/backup callbacks. Ошибка до commit откатывает DDL и version на копии. При остановке после commit для проверки всё равно нужен успешный отчёт. Рабочая база не заменяется, downgrade не выполняется.

## Репетиция схемы черновиков Stage2

Для источника со схемой 2 добавьте `--to-schema 3` и укажите новый каталог вывода. На копии появится пустая таблица `change_plan_drafts` с ревизией, автором, ресурсом, исходным состоянием и хешем для операции `docker.restart`. Проверка сохранности охватывает все таблицы схемы 2, включая очередь, ключи идемпотентности и инциденты. Без флага команда сохраняет прежнее поведение 1 → 2.

Установщик и новые экземпляры Controller используют схему 3. Rescue читает архивы схем 1–3. При импорте схемы 3 прежние черновики очищаются, а события Audit/Outbox сохраняются.

## Проверка сохранённой репетиции

```bash
/opt/hostorbit/venv/bin/python -m hostorbit.runtime.migration_review /var/tmp/hostorbit-migration-review-001
```

Запустите проверку от владельца приватного каталога до тестового редактирования копий. Утилита заново читает обе SQLite, сверяет схемы, целостность, исходные строки, Audit/Outbox и дайджесты отчёта. В мигрированной копии должно быть ровно одно новое событие миграции и пустые новые таблицы. Успех возвращает `REHEARSAL_VERIFIED`; `live_apply` остаётся `BLOCKED`.

Для AC-28 можно начать с чистой тестовой установки. Перенос существующей рабочей БД в этом сценарии не требуется. Схема 3 создаётся установщиком. HTTP API поддерживает черновик, preflight, Backup Gate и подтверждение с заблокированным выполнением.

## Предварительная проверка ControllerBackup для рабочей миграции

После успешного `hostorbit-backup publish` запустите на Controller:

```bash
sudo /opt/hostorbit/venv/bin/python -m hostorbit.runtime.migration_backup \
  --snapshot-id ID_СНИМКА
```

Проверка сверяет подпись снимка, его Controller и версию рабочей схемы, запись `PUBLISHED` в локальном журнале и защищённую квитанцию для текущего SFTP-назначения. Возраст считается от начала барьера захвата с запасом на suspend. Смена загрузки или возраст свыше 30 минут требуют нового снимка. Поле `maximum_age_seconds` показывает верхнюю оценку возраста. Время публикации и системное UTC на расчёт не влияют.

Проверка записи о публикации возвращает `FRESH_PUBLICATION_RECORDED`.

Чтобы проверить и саму копию, скачайте через отдельный доступ для восстановления все три файла из завершённого SFTP-каталога снимка. На Controller поместите их в отдельный каталог Root с правами `0700` и выставьте каждому файлу права `0600`. В каталоге должны быть только `COMPLETE`, `provenance.json` и `controller.age`.

```bash
sudo /opt/hostorbit/venv/bin/python -m hostorbit.runtime.migration_backup \
  --snapshot-id ID_СНИМКА --downloaded-copy /var/tmp/hostorbit-backup-check
```

Команда сверяет размер и SHA-256 каждого файла с данными подписанного снимка и квитанции. Возраст проверяется после чтения. Успех возвращает `FRESH_BACKUP_COPY_VERIFIED` для предоставленного комплекта. Скачивание выполняется отдельно, поэтому доступность SFTP на момент миграции проверяется отдельно. В обоих режимах `backup_gate: DENIED`. Независимость площадки и возможность восстановления требуют своих проверок.

## План проверки подписанного обновления

Из доверенного checkout на Controller свяжите подписанный выпуск, репетицию для соответствующей пары схем и скачанную копию опубликованного архива:

```sh
sudo /opt/hostorbit/venv/bin/python -m deploy.prepare_migration ./release-1.2.0 \
  --trust-key /etc/hostorbit/release.pub \
  --installed 1.1.0 --bootstrap 1.0.0 --minimum-release 1.1.0 \
  --schema 2 --vault-format 1 --review /var/tmp/hostorbit-migration-review-001 \
  --snapshot-id ID_СНИМКА --downloaded-copy /var/tmp/hostorbit-backup-check
```

Подставьте фактические версии и параметры выпуска. Команда перепроверяет подпись и архив, схему и содержимое обеих копий SQLite, скачанный бэкап и подписанный TimeHealth от Supervisor того же экземпляра. Рабочую БД читает в отдельной read-only транзакции и сверяет дайджест всех строк с репетицией. При изменении БД требуется новая репетиция.

`MIGRATION_INPUTS_VERIFIED` возвращает план и его SHA-256. План привязан к манифесту выпуска, источнику SQLite, квитанции бэкапа и поколению Supervisor. Результат относится к моменту проверки. При запуске рабочей миграции все условия потребуется сверить повторно под допуском. `live_apply` остаётся `BLOCKED`, а `backup_gate` — `DENIED` до проверки восстановления и независимого размещения копии.

## Подпись владельца под результатом восстановления

После проверки конкретного снимка на изолированном Controller сохраняются фактические результаты восстановления. Владелец сверяет их и подписывает отдельным ключом Ed25519. Закрытый seed остаётся на машине владельца. JSON для подписания содержит `v: 1`, `type: "hostorbit.controller-migration-restore"`, `source_instance`, `snapshot_id`, `marker_sha256`, `schema`, `tested_at` (UTC Unix seconds) и объект `checks`. Каждая проверка должна быть пройдена: `restored_in_isolation`, `sqlite_audit_verified`, `owner_login_verified`, `independent_storage_verified`.

```sh
umask 077
python -m deploy.controller_restore_attestation \
  --claims restore-claims.json --evidence restore-report.txt \
  --signing-key /secure/owner-restore.seed > restore-attestation.json
```

Передайте в `deploy.prepare_migration` параметры `--restore-attestation`, `--restore-evidence` и `--owner-verify-key`. Файлы подписи и свидетельства хранятся у root с правами `0600`. Публичный ключ владельца доверяется отдельно от ключей Controller и выпуска. Проверка привязывает подпись к снимку, квитанции, схеме и данным отчёта. При проверке используется подписанное время Supervisor. Принимаются свидетельства возрастом до 30 минут.

`OWNER_RESTORE_ATTESTATION_VERIFIED` подтверждает подпись владельца и совпадение данных. Изоляцию и независимость площадки подтверждает владелец фактическим прогоном. Идентификатор подписанного свидетельства входит в SHA-256 плана. Используйте этот SHA-256 для локального утверждения плана.

## Применение обновления API и Worker

Запускайте на Controller из доверенного checkout с Python установленного HostOrbit. Подготовьте подписанный выпуск, совместимые образы API и Worker, свежий опубликованный снимок и подписанный отчёт владельца о проверке восстановления. Заранее загрузите образы в Docker по полным OCI-ссылкам с `@sha256:`. Их дайджесты должны совпадать с манифестом. После просмотра preflight сохраните root-файл `0600` с полями `plan_id`, `revision`, `approval_id`, `plan_sha256`. Поля идентификаторов принимают ULID, ревизия начинается с 1, SHA-256 берётся из preflight с тем же свидетельством владельца.

```sh
sudo /opt/hostorbit/venv/bin/python -m deploy.application_update ./release-1.2.0 \
  --trust-key /etc/hostorbit/release.pub --approval /root/update-approval.json \
  --installed 1.1.0 --bootstrap 1.0.0 --minimum-release 1.1.0 \
  --schema 2 --vault-format 1 --review /var/tmp/hostorbit-migration-review-001 \
  --snapshot-id ID_СНИМКА --downloaded-copy /var/tmp/hostorbit-backup-check \
  --restore-attestation /root/restore-attestation.json \
  --restore-evidence /root/restore-report.txt --owner-verify-key /root/owner-restore.pub \
  --api-image "$API_IMAGE_REF" --worker-image "$WORKER_IMAGE_REF"
```

Supervisor переводит Controller в обслуживание. Команда останавливает Compose, блокирует автоматический запуск через systemd и повторно сверяет выпуск, состояние БД и бэкап. Схема и аудит обновляются в одной SQLite-транзакции. После её фиксации команда меняет ссылки на образы, запускает службы и ждёт успешного старта до снятия режима обслуживания. Поддерживаются переходы 1 → 2 и 2 → 3. Статический WebUI и хостовые службы обновляются отдельно.

При отказе до COMMIT команда проверяет версию схемы и может запустить прежние службы под ограничениями Supervisor. После COMMIT прежняя версия служб может оказаться несовместимой со схемой, поэтому при ошибке команда блокирует запуск и сохраняет БД в её текущем виде. Если остался `/var/lib/hostorbit/application-update/pending.json`, проверьте фазу, реальную версию SQLite, текущие образы и состояние Supervisor перед восстановлением. Повторный запуск блокируется. При проверке статуса после SIGKILL используйте схему в БД как источник истины для факта COMMIT.

Тесты репетиции покрывают committed WAL, параллельную запись, сохранение Auth/session и целостности аудита. Тесты применения используют реальную SQLite и Supervisor с адаптером служб для проверки COMMIT, отката и SIGKILL. Прогон с реальными systemd и Docker Compose для применения обновления предстоит на чистом Controller со снимком и отдельным восстановлением. [Действующая проверка Foundation](../evidence/revalidation/stage1-current/README.md).
