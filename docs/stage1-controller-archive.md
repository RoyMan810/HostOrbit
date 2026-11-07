# Локальный подписанный Controller archive

Публикация созданного архива теперь доступна отдельным [SFTP transport](stage1-sftp-publication.md); `create` по-прежнему заканчивается локальным `SIGNED` и не выполняет сеть. Restore/freshness gates остаются закрытыми.

`hostorbit-backup create` собирает согласованный снимок поддержанного Controller/Vault, экспортирует working DEK прямо в age encryption stream и подписывает ciphertext вместе с canonical data manifest. Результат — `LOCAL_SIGNED_ONLY`: SFTP publication вызывается отдельно; restore attestation, импорт на новую VPS и Backup Gate ещё не реализованы. Наличие этого файла не разрешает migration/update.

## Создание и проверка происхождения

На Controller локальный Root задаёт **публичный** native age/X25519 recipient владельца. Приватная Owner identity этой команде не передаётся:

```bash
sudo /opt/hostorbit/venv/bin/hostorbit-backup create --recipient age1...
```

Root-private capture directory содержит `controller.age`, `provenance.json`, Controller staging files и manifest. Каталоги 0700, файлы 0600. Команда возвращает пути/дайджесты и явные `off_host=false`, `restore_verified=false`, `backup_gate=DENIED`. Working ciphertext и данные не перезаписывают предыдущий snapshot.

Владелец должен независимо сохранить public signing anchor из `/etc/hostorbit/gate.pub` до доверия к архиву. Проверка использует именно этот сохранённый ключ; ключ внутри самого архива не подставляется автоматически:

```bash
hostorbit-backup verify --ciphertext controller.age \
  --provenance provenance.json --trusted-key independent-controller.pub
```

Проверяются Ed25519 signature, protocol domain, exact ciphertext digest/length, manifest и выбранный recipient. Ответ `PROVENANCE_VERIFIED` явно сохраняет `payload_integrity=NOT_DECRYPTED`: это не проверка расшифрованного payload и не restore test. Root Gate signing identity используется с отдельным строгим domain `hostorbit.controller-backup`; существующие Worker/Broker RPC не предоставляют generic signing/export.

## Согласованная точка

Coordinator записывает baseline instance/epoch, recipient и пределы в root-private request metadata, закрывает business admission и ждёт drain до 60 секунд. Под exclusive barrier до 30 секунд он повторно проверяет drain/epoch, фиксирует [Broker pin](stage1-vault-pins.md), делает Online Backup API copies App/Gate SQLite, проверяет integrity/foreign keys/audit-outbox chain и записывает полный manifest. Schema 1 и 2 копируются с их исходной версией; рабочая БД не мигрируется.

Архив содержит App/Gate DB, runtime/target policy, публичный Gate anchor, installation metadata, подписанный release manifest и его public trust key/signature, dependency hash lock, SBOM и Compose config. Проверяются соответствие protected policy Gate digest, неизменность runtime config, наличие Secret References и source commit. Все referenced Vault ciphertext versions и receipt journal находятся в отдельном Broker pin. Dependency identity закреплена release/lock/SBOM; сами wheel/OCI distributions не дублируются в data archive и должны быть доступны из доверенного совместимого release при восстановлении.

Root authority signing private key, host OS master key, encrypted runtime credential и offline Owner identity в payload не включаются. Восстановление должно создавать новую host-bound credential и независимую Gate identity/instance/epoch, запускаться в READ_ONLY_RECOVERY и требовать manual fencing/rotation; автоматический запуск копии live Gate DB этой реализацией не добавлен.

После self-contained local capture Coordinator записывает `BARRIER_RELEASED` и открывает writer admission. Только затем отдельный Broker-UID systemd process получает framed Controller members через stdin, повторно проверяет immutable pin/digests/AAD/key fingerprint и передаёт tar stream в закреплённый host `age`. Root получает только ciphertext. Portable keyset из памяти Broker включён как отдельный member **внутри** age stream; plaintext DEK/tar/identity файл не создаётся. Все members имеют фиксированные имена и regular-file metadata; paths, symlinks и generic extraction не принимаются.

Native sealer имеет readonly filesystem, no capabilities, AF_UNIX only/private network, OS credential, core limit 0 и independent cgroup runtime bound. Глобальный writer lock во время encryption/signature не удерживается. При успешном age exit и завершённой передаче записываются `SEALED → SIGNED`; ошибка/ENOSPC/утрата ключа/изменённый pin дают `FAILED`, а повреждённый control journal закрывает admission до восстановления. Файл сам по себе не повышает durable статус. Прерванные post-barrier captures сохраняются private и не объявляются опубликованными.

## Поддержанный профиль и оставшиеся gates

Working Vault пока имеет только DEK generation 1. Она переносится даже для пустого Vault; другая generation или неподдержанная замена credential дают отказ. Предварительный reserve учитывает staging и ciphertext, предел metadata DB — 512 MiB каждый, до 65 536 secret versions. Нет автоматического retention/GC/release pins; staging/pins остаются private до последующей политики завершения/очистки.

Capture time записывается с `time_trusted=false`. Данные пригодны для проверки выбранной recovery point, но не являются `PRECHANGE_BACKUP_FRESH`. [Rescue data import](stage1-rescue.md) добавляет строгий workstation preflight, memory-only verification/repackage, exact Owner digest/auth и новый read-only data layout. Остаются signed TimeHealth freshness binding, lifecycle recovery/retention, подключение recovery layout к signed installer, независимый service restore, manual fencing/activation и restore attestation. Update/schema migration и Backup Gate остаются закрытыми.

Unit tests расшифровывают fixture archive, открывают оба Vault objects переносимым DEK, сверяют Owner/audit/state и проверяют запись после barrier, историческую schema 1, wrong anchor/recipient, changed ciphertext/key/config, truncated input и path expansion. Signed-installation CI выполняет тот же native path под реальными UID/systemd credentials, с public anchor, сохранённым до создания. Fixture Owner identity остаётся в памяти внешнего CI driver; age-keygen не устанавливается в Controller. Физически это одна disposable Ubuntu VM: тест не является независимым off-host disaster recovery, production Rescue preflight или Owner attestation и не переводит AC в PASS.
