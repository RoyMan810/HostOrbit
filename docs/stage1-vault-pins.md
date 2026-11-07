# Broker-private Vault pin

`hostorbit.runtime.pins` создаёт локальную часть будущего согласованного ControllerBackup: Vault metadata, journal квитанций Broker и все referenced ciphertext objects, включая отозванные версии. Это **LOCAL_PIN_ONLY**: portable DEK ещё не экспортируются, Backup Gate остаётся `DENIED`, age/provenance/SFTP/restore сюда не входят.

Root Coordinator вызывает `capture_with_systemd(snapshot_id)` только под exclusive [writer barrier](stage1-backup-barrier.md). Фиксированный native helper запускается отдельным процессом с UID/GID Broker, `LoadCredentialEncrypted`, без capabilities и сетевых address families. Он не занимает синхронный SSH Broker. RuntimeMaxSec 20 секунд и KillMode control-group действуют независимо от жизни вызывающего Root процесса; вызов/cleanup имеют отдельные короткие тайм-ауты. Будущий полный capture должен резервировать этот бюджет внутри общего barrier deadline.

Helper читает только установленную root-owned runtime configuration. Локальная `hostorbit-runtime pin-vault --snapshot-id <id>` принимает только UID Broker. Web/Worker IPC для pin/export отсутствует. Проверяется точный Root latch с тем же snapshot ID и наличие exclusive kernel lock; одного написанного состояния `SHORT_BARRIER` недостаточно. Сам по себе pin не удостоверяет, кто держал lock: будущий Controller manifest/provenance обязан связывать его с независимым завершённым Coordinator capture.

## Состав и проверка

Новый private каталог `/var/lib/hostorbit/broker/snapshot-pins/<snapshot_id>` создаётся без overwrite. Каталоги имеют mode 0700, файлы 0600 и принадлежат Broker.

- `vault.sqlite3` и `receipts.sqlite3` снимаются SQLite Online Backup API с committed WAL, проверкой integrity/foreign keys/user_version и переводом копий в standalone DELETE journal mode. Копирование выполняется страницами с deadline/barrier checks; live DB/WAL/SHM не копируются файловой парой.
- Каждый referenced object проверяется по SHA-256 и AEAD с исходным canonical metadata AAD. Schema/reference, immutable version, purpose, owner/consumers digest и поколение ключа проверяются до завершения pin. `REVOKED` сохраняется и не становится разрешением Use; immutable AAD хранит исходное `ACTIVE` отдельно от текущего состояния строки. Непривязанные orphan objects не включаются.
- `pin.json` записывается после fsync файлов и содержит их размеры/дайджесты, reference/state/AAD digests и fingerprint нужного working DEK. Ни DEK, ни открытый SSH key в pin не записываются и не возвращаются вызывающему процессу. Fingerprint нужен для последующего отказа при неподдержанной замене credential до age export.

Сейчас runtime Vault имеет только generation 1. Pin включает generation 1 даже для пустого Vault и отказывает при неизвестном поколении вместо создания неполного архива. Многопоколенная DEK rotation, GC/retention, durable release pins и переносимый keyset будут отдельными изменениями; текущая операция их не имитирует. Локальные staging copies могут содержать чувствительные метаданные и остаются private; автоматическое удаление live Vault не выполняется.

Поддержанный предел этого native helper: до 512 MiB logical pages на каждый metadata journal и до 65 536 версий секретов. До создания pin проверяется свободное место по logical DB pages, максимальным ciphertext sizes и резерву metadata. Выход за предел, ENOSPC, повреждённый object/AAD, утраченный barrier и ошибка helper не дают завершённого результата. Частичный каталог сохраняется без пригодного completion proof; после SIGKILL окончательное решение всегда принадлежит независимому Coordinator journal, а не наличию `pin.json`.

## Стенд

Unit tests проверяют active/revoked версии, committed WAL, неизменность копии после новых import/revoke/receipts, отсутствие plaintext ключей, empty Vault, чужой snapshot, отсутствие exclusive lock, overwrite, неизвестную generation, повреждение AAD/ciphertext, недостаток места и потерю latch. Отдельный тест отказывает непривилегированному вызову native launcher до загрузки credential.

Signed-installation CI создаёт собственный одноразовый SSH fixture key, импортирует две версии под настоящим UID Broker, отзывает одну и запускает установленный helper через настоящий systemd credential под Root barrier. Проверяются copied files/digests/state и сохранение `portable_keys_exported=false`, `backup_gate=DENIED`. Пользовательский VPS и его SSH keys в этом стенде не участвуют. Эти проверки не переводят приёмочные AC Stage1/MVP в `PASS`.
