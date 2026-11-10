# Offline Rescue и импорт данных Stage1

`hostorbit-rescue` проверяет ControllerBackup на offline workstation, перепаковывает на одноразовый recipient новой машины и импортирует данные в новый приватный каталог. Результат — **данные в READ_ONLY_RECOVERY**, с новым Gate signer/instance/epoch и новым host-bound OS seal для переносимого DEK. Службы устанавливаются отдельным [signed recovery installer](stage1-recovery-installation.md), с сохранением read-only profile. [Локальная Owner activation](stage1-recovery-activation.md) реализована отдельно; независимый DR-прогон и ручная приёмка fencing/rotation остаются открытыми.

## Доверенная workstation

Поддержан узкий профиль Ubuntu 24.04 и новее, amd64 под Root (native offline-профиль дополнительно проверен на отдельной VM Ubuntu 26.04): нет установленного Controller, swap полностью выключен, kernel не предлагает `disk` в `/sys/power/state`, процесс видит только loopback в своём network namespace, доступно не менее 3 GiB RAM. Загрузка с `nohibernate` отключает hibernation/resume; одного отключения systemd target недостаточно. Основание: [Linux kernel boot parameters](https://www.kernel.org/doc/html/v6.8/admin-guide/kernel-parameters.html). Изолированная workstation, её ОС, терминал и администратор входят в доверенную границу. Network namespace ограничивает IP-связность процесса; это не свидетельство физической независимости машины.

`preflight` и `repackage` проверяют профиль без флага обхода. Перед вводом identity выключаются core dumps и Linux dumpability. Поддержан memory-only payload до 512 MiB вместе с USTAR framing; большие архивы отклоняются как неподдержанные. Plaintext identity, portable DEK и расшифрованный tar не сохраняются во временные файлы. SQLite проверяется через `deserialize` в памяти, `temp_store=MEMORY`, `trusted_schema=OFF`, query-only, limits и deadline. Очистка Python buffers выполняется best effort: отсутствие всех остаточных копий в DRAM/SQLite/age/ядре не гарантируется.

Используется тот же age v1.3.2 Linux amd64, что и при создании архива. Проверяются binary digest и доверенные владельцы/права всех родителей. Для генерации одноразового target key отдельно проверяется `age-keygen` из того же upstream release: SHA-256 `0a0009db842259d6717f7eeb30acb6b90d2a2eb924c6acd0a0db0ca1f1537899`. Он не добавляется в обычную Controller-установку. Rescue-инструменты и Python package должны поступить из доверенного комплекта; автоматическая доставка отдельного signed Rescue kit ещё не реализована.

## Протокол

1. На новой машине Root резервирует **два новых** каталога в заранее созданном root-owned приватном parent: state и destination. Даже существующий пустой каталог не присваивается инструментом. `request` генерирует native X25519 identity проверенным `age-keygen`, сохраняет только `systemd-creds --with-key=host --name=rescue-identity` ciphertext и durable ledger. Публичный запрос содержит target ID, recipient/fingerprint, challenge, hash исходного provenance envelope и срок 900 секунд. Секрет новой машины отличается от offline Owner identity.
2. На offline workstation Owner независимо сверяет публичный запрос и использует заранее сохранённый Controller signing anchor. Подпись внешнего envelope и hash исходного ciphertext проверяются **до расшифровки**. Проверяется тот же открытый inode до и после age. Возраст исходной recovery point не ограничивается 15 минутами: срок относится только к новому запросу/bundle.
3. В памяти проверяются точный USTAR dialect, уникальность и whitelist members, размеры/digests всех файлов, source manifest, Vault pin, SQLite integrity/FK и точная release-defined schema всех четырёх БД, Audit/Outbox chain, Owner, Gate instance/epoch/policy, referential completeness Vault и AEAD каждой active/revoked версии. Неожиданные SQLite triggers/tables и неизвестные поколения DEK отклоняются; сейчас runtime поддерживает только generation 1. Содержимое архива не исполняется; старые runtime paths и release metadata не управляют импортом. Историческая App schema 1 импортируется как schema 1 без запуска DDL migration.
4. Проверенные self-contained данные шифруются непосредственно в age pipe для одноразового recipient. Review показывает полный `bundle_sha256`, исходный ciphertext hash, envelope hash, fingerprint, target ID, challenge, expiry и состав. На диск workstation записывается только новый encrypted bundle. Существующий output не перезаписывается.
5. На target Owner переносит **полный SHA-256 из review отдельно от bundle**, через удостоверенную локальную Rescue-консоль. CLI не принимает digest или пароль через аргумент, environment, stdin pipe либо WebUI. Проверяются exact ciphertext hash, binding, source signature, payload integrity и отдельный пароль активного Owner из исходной БД. Пять неверных Owner auth закрывают запрос. UTC expiry дополняется boot ID и monotonic deadline: reboot или откат часов не продлевают запрос.
6. После повторной проверки пустоты и свободного места ledger устойчиво переходит в `IMPORTING` **до первой записи данных**. Успех — `IMPORTED`, ошибка — `FAILED`; kill оставляет одноразово погашенный `IMPORTING`. Повторного использования/продолжения поверх частичного каталога нет. Требуется новая пустая цель и новый запрос. После успешного импорта encrypted one-time identity удаляется; физическое стирание старых блоков не заявляется.

Пример имён путей (без secrets в shell):

```sh
sudo install -d -m 0700 /var/lib/hostorbit-rescue
sudo hostorbit-rescue request \
  --state /var/lib/hostorbit-rescue/request-1 \
  --destination /var/lib/hostorbit-rescue/recovered-1 \
  --source-envelope-sha256 <independently-verified-envelope-sha256>
```

На workstation `sudo unshare --net hostorbit-rescue preflight` должен пройти **до** ввода Owner identity. `repackage` принимает только пути к ciphertext, provenance, отдельно сохранённому public anchor, публичному request и новому output. Identity вводится скрыто с терминала и передаётся age через anonymous pipe; она не доставляется на target. На target `hostorbit-rescue import --state ... --bundle ...` интерактивно запрашивает независимый digest и затем Owner username/password.

## Состояние после импорта

Приватный каталог содержит рабочую App DB, Vault metadata/ciphertext objects, свежие Broker/Gate journals, новую encrypted OS credential и исходные configs/manifest/Gate DB/receipts в `source/` только как свидетельства. Старый signer, host master key и encrypted source credential не копируются. Старые sessions/reauth/bootstrap удаляются; QUEUED jobs получают `CANCELLED_SAFE`, остальные незавершённые — `UNKNOWN_OUTCOME`, ресурсы отключаются. Незавершённые Jobs обрабатываются внутри одной транзакции партиями до 128 записей, без загрузки всей очереди в память. Каждый новый карантин Job фиксируется атомарным `job.finished` в Audit/Outbox; для старых импортов Timeline показывает сохранённое событие `recovery.imported` с явным источником, не дописывая исторический журнал. В Audit/Outbox также добавляется импорт с source/bundle hashes. ACL/AAD и состояния REVOKED сохраняются без автоматического переназначения numeric consumers.

Writer admission получает отдельный устойчивый `recovery-profile.json`. Он блокирует business writes и dispatch даже при утрате заменяемого snapshot `state.json`; Auth/Audit control transactions разрешены. Coordinator restart/watchdog не снимает этот профиль. Новая Authority имеет `activated=0`, `RECOVERY_HOLD`, новый signer и target instance; она отклоняет даже read-only SSH permit. Старые Gate attempts и Broker receipts не становятся новой authority. Force-active/force-open интерфейса нет.

`services_installed=false`, `restore_verified=false`, `backup_gate=DENIED`. До установки/ручной активации ничего не запускается. Все managed targets требуют fencing, credential rotation и quarantine reconciliation. Исходный signed archive должен сохраняться: импортные служебные журналы не заменяют backup.

## Проверки и ограничения evidence

Unit/fault tests проверяют точный Owner digest при подменённых DB/DEK с правильными внешними полями, чужой target/challenge, replay, expiry, Owner auth/lockout, непустую цель, ENOSPC и погашение failed import, старую recovery point, malformed tar, corrupted scope/generation, отзыв исходных sessions/jobs и durable read-only после restart/утраты latch. Отдельно проверяются отказы workstation profile и неинтерактивной консоли.

Signed-installation CI запускает код из установленного wheel, настоящий pinned age/keygen и systemd-creds на временной GitHub-hosted Ubuntu VM. Проверяются native import/new credential/Vault decryption/new signer, Auth, отказ business writes, replay и watchdog. Положительная процедура использует явно обозначенную **CI profile fixture**; production preflight обязан отклонить уже установленный Controller. Этот прогон **не удостоверяет** реальную offline workstation, новую независимую физическую машину, полный service restore или manual restore attestation. AC статусы и общий Stage1/MVP gate не повышаются автоматически.

## Проверка архива ресурса Stage2

`hostorbit-rescue verify-resource-archive` проверяет один формат архива остановленного тестового Docker named volume на той же изолированной workstation. Укажите `--ciphertext`, `--provenance`, отдельно сохранённый открытый 32-байтовый ключ Ed25519 `--trusted-key` и ожидаемую версию приложения `--application-schema`. Секретный ключ age вводится скрыто через локальный терминал.

Подпись внешнего envelope связывает версию схемы, SHA-256 и длину ciphertext и SHA-256 внутреннего манифеста. Пути файлов и их метаданные остаются внутри шифротекста. Проверка принимает только обычные файлы и каталоги с явно заданными UID, GID и правами. Ссылки, специальные файлы и расширенные метаданные не входят в формат. Время создания возвращается как точка восстановления. Вчерашний архив проходит те же проверки, что и свежий.

Успех CLI возвращает `INTEGRITY_VERIFIED` и `restore_eligibility=NOT_EVALUATED`. Остановка сервиса, UID, GID, права и получатель age описаны подписавшей стороной. Проверка подтверждает целостность этих сведений и расшифровку предоставленным ключом.

Компонент [проверки аттестации](../hostorbit/runtime/resource_restore_attestation.py) проверяет канонический JSON с подписью Ed25519 от отдельно доверенного ключа Owner. Запись фиксирует схему приложения, SHA-256 версии процедуры, время ручного теста, хеш тестового архива и хеш файла доказательств. Подписанные проверки включают новую пустую цель, данные и метаданные, проверку приложения и отказ на занятой цели. Проверка принимает время от доверенного вызывающего кода и отклоняет запись с момента истечения 90 дней.

`verify_restore_source` проверяет выбранный архив и аттестацию процедуры вместе. Тестовый архив в аттестации может отличаться от выбранной точки восстановления. Результат сохраняет `restore_eligibility=NOT_EVALUATED`. Проверка подписи подтверждает происхождение заявления Owner и целостность доказательства.

На целевом Linux-хосте [`check_restore_target`](../hostorbit/runtime/resource_restore_target.py) сверяет имя и ожидаемый `CreatedAt` заранее выбранного тома с локальным Docker Engine. Проверка принимает только стандартный локальный том без параметров монтирования. Она проверяет пустоту каталога, свободные байты и inode по переданному бюджету и отсутствие ссылок от контейнеров по данным Docker. Каталог открывается без перехода по ссылкам и через границы монтирования внутри каталога данных Docker.

`EMPTY_TARGET_CHECKED` описывает состояние на момент проверки. Для записи нужны создание и резервирование отдельного тома, повторная проверка перед записью и ручное подтверждение. Сквозное восстановление и приёмка AC-B05 остаются открытыми.
