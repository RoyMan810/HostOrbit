# Публикация Controller archive по SFTP

`hostorbit-backup publish --snapshot-id <id>` передаёт существующий [локальный подписанный архив](stage1-controller-archive.md) на отдельно настроенный SFTP target. Команда требует локального Root, проверяет исходную подпись/ciphertext и не принимает произвольные local paths, remote paths, URL или Secret Reference из Web/Worker.

Успех `PUBLISHED` означает подтверждённую публикацию на настроенном SSH receiver: ciphertext/provenance/marker прочитаны обратно и совпадают. `off_host=true` относится к настроенному remote target; IP/SSH verification не доказывает независимое питание/диск/гипервизор. `failure_domain_verified=false`, `restore_verified=false`, `backup_gate=DENIED` остаются явными. Независимость хранилища — отдельное требование развёртывания и приёмки, не автоматический вывод из успешного SSH.

## Защищённая конфигурация и ключ

Новая установка создаёт `/etc/hostorbit/backup-target.json` (root-owned 0644) с `{"v":1,"enabled":false}`. Destination не появляется автоматически из inventory. Root задаёт version/enabled, ULID id, canonical numeric IP, port, allowed CIDRs, полный проверенный Ed25519 host public key, username, absolute directory, Secret Reference и policy revision. DNS, loopback/link-local/metadata, mapped IPv6, plugins, path traversal, неизвестные fields и небезопасные имена отклоняются. Каталог remote prefix должен существовать; каждый компонент проверяется через lstat без symlinks.

Пример структуры до подстановки проверенных оператором значений:

```json
{
  "v": 1,
  "enabled": true,
  "id": "01JCYQZ4T9V8MNVYEH3D2M7Q1F",
  "ip": "203.0.113.10",
  "port": 22,
  "allowed_cidrs": ["203.0.113.10/32"],
  "host_key": "ssh-ed25519 <independently-verified-server-public-key>",
  "username": "hostorbit-backup",
  "directory": "/store/hostorbit",
  "secret_ref": "01JCYQZ4T9V8MNVYEH3D2M7Q1E:v1",
  "policy_revision": 1
}
```

Private SSH identity импортируется локальным `hostorbit-runtime import-backup-key` под UID Broker с OS credential. Его AAD имеет отдельные `purpose=backup.sftp`, consumer UID Broker, target ID и policy revision. `host.probe` key, чужой consumer/target/revision и отозванная версия не подходят. Команда не добавляет новый managed-host adapter или secret-return RPC. Root invocation использует тот же `LoadCredentialEncrypted` profile, что и provisioning Vault; исходный private SSH file должен быть Broker-owned 0600. Offline Owner age identity этому процессу не передаётся.

Transport credential, его ciphertext и metadata входят в следующий Vault pin/age archive; target config тоже захватывается. Старые подписанные snapshots без этого optional config member продолжают проходить provenance verification. Их recovery point не переписывается при публикации. Для скачивания после потери Controller нужен независимо доступный recovery access к SFTP, а не только transport key, находящийся внутри самого архива.

## Протокол

Root сохраняет immutable publication request с target digest и exact signed source digests, записывает `UPLOADING` в отдельном control journal и запускает отдельный sandboxed Broker process. Framed stdin содержит только signed provenance и encrypted archive. Broker создаёт private encrypted local staging, проверяет подпись по установленному Root public anchor, затем использует Vault identity только в памяти AsyncSSH. Agent, SSH config, password/KBI/GSS/host-based auth, forwarding и exec/shell channel выключены; открывается только SFTP subsystem. Native process не имеет capabilities и имеет core/memory/runtime bounds.

Upload не держит writer barrier. На checkpoint заново проверяются authoritative Vault state/AAD и root-owned target digest. Изменение target или revoke запрещает дальнейшее завершение. Уже аутентифицированную внешнюю SSH session нельзя отозвать криптографически; ограниченный процесс/тайм-аут и safe checkpoints ограничивают её использование.

1. Создаётся новый private `.<snapshot_id>.<random>.partial` без overwrite.
2. Ciphertext и provenance пишутся exclusive-create 0600 во временные имена. Каждый файл получает remote `fsync`, затем полностью читается обратно с bounded SHA-256/size check и переименовывается внутри staging.
3. Последним файлом становится canonical `COMPLETE`: id, target digest, ciphertext digest/length и provenance digest. Он тоже проходит fsync/readback.
4. Последнее не допускающее overwrite переименование staging directory в `<snapshot_id>` делает результат видимым для lookup завершённых архивов. Dot/partial каталоги не eligible даже при наличии marker внутри.
5. Final directory заново проверяется: ровно три regular files, ожидаемые bytes/digests. Только после подтверждённого helper receipt Root сохраняет receipt, добавляет `backup.published` Audit/Outbox после исходной snapshot sequence и фиксирует `PUBLISHED`.

Потеря последнего ACK или смерть Root оставляют `UPLOADING/FAILED`, не автоматический успех. Повтор для того же target/source проверяет уже существующий final без re-upload/overwrite; corrupted/incomplete final даёт отказ. Existing data и remote partials код не удаляет. Другой target/source не может подменить immutable request: требуется отдельная новая операция/snapshot. Ошибка сети/ENOSPC/unsupported fsync/readback/revoke даёт `FAILED`; ошибка control commit закрывает admission до durable recovery. Счётчик/наличие local ciphertext не являются фактом завершённой публикации.

Поддержан один protected destination, native Ed25519 keypair, archive до 4 GiB, общий transfer bound 120 секунд и systemd cgroup bound 150 секунд. Server должен поддерживать fsync extension и non-overwriting rename; более слабый fallback отсутствует. Remote file fsync/readback опираются на корректность SFTP server/FS: аппаратная power-loss durability и защита от удаления хранилищем ими не доказываются. Server должен независимо ограничивать account правами SFTP и хранить protected recovery copies; клиент не вызывает shell, chmod чужих файлов, overwrite или delete.

## Проверки и оставшийся объём

Contract tests вводят corruption, ENOSPC, lost final ACK, revoked credential и unsupported fsync. Root tests проверяют durable FAILED/PUBLISHED, отсутствие barrier во время upload, immutable target/source binding, strict receipt и единственный audit event при retry. Signed-installation CI поднимает настоящий OpenSSH в отдельном network namespace/chroot, проверяет установленный Broker-UID path с OS credential, decrypt portable payload из опубликованных bytes, wrong host, outage/retry, реальный ENOSPC на receiver tmpfs, corrupted final и revoke. Физически это одна disposable hosted VM; user VPS/keys не используются, независимый disaster recovery не аттестован, AC не повышаются до PASS.

Следующие gates остаются открытыми: signed TimeHealth freshness для pre-change, lifecycle reconciliation/retention/release pins после restart, независимый DR, manual fencing/activation и restore attestation. [Rescue data import](stage1-rescue.md) реализует preflight, одноразовый challenge, exact Owner digest/auth; [recovery installer](stage1-recovery-installation.md) запускает из этих данных службы в READ_ONLY_RECOVERY. Publication transport не открывает update/migration.
