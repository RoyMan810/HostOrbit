# Установка восстановленного Controller в READ_ONLY_RECOVERY

Signed development installer принимает `--recovery-state` — путь к завершённому локальному Rescue ledger. Установка использует уже проверенный и отдельно подтверждённый Owner импорт; она не принимает произвольный unpacked archive, старый runtime config или готовую БД без ledger. Требование свежих пустых installation namespaces сохраняется. Переустановка поверх существующего Controller, `--targets` вместе с recovery и автоматическая активация отклоняются.

## Проверка и перенос

После независимой проверки подписи всего bundle установщик создаёт приватный временный venv только из его hash-pinned wheelhouse. Recovery preflight выполняется кодом этого проверенного wheel и проверяет Root ownership/permissions, `IMPORTED` ledger, отсутствие одноразовой identity, совпадение receipt/request/bundle hash, подписанный source provenance и pin, protected policy, Audit/Outbox и точную App schema. Gate должен принадлежать текущему host, иметь новый target instance/signer, `activated=0`, `RECOVERY_HOLD` и не иметь attempts. Проверяются quarantine ресурсов/незавершённых jobs, новая host-bound credential, точная Vault schema, pin completeness и AEAD всех active/revoked объектов. Owner identity не требуется и на Controller не доставляется.

Транспортный expiry повторно не применяется к уже импортированным данным: успешный одноразовый импорт можно установить позже. `--check` не создаёт installation namespaces и не погашает импорт. Он может создавать временный verified venv и SQLite read-side WAL metadata; business state исходного импорта не изменяется. Нужны исходный Root-private ledger и его импортированный каталог на этой же новой машине; перенос только encrypted OS credential на другой host не поддерживается.

Перед переносом данных записывается Root-private `installation.claim.json` с target ID, bundle hash, digest проверенного install artifact и read-only mode. `O_EXCL` запрещает повторное использование. Crash/ENOSPC после claim не превращается в успешный install и не разрешает повтор поверх частичного состояния. Автоматического resume/cleanup продукта нет; частичная installation остаётся закрытой для разбора, восстановление повторяют в новых пустых namespaces.

App/Vault DB переносятся SQLite Online Backup API с проверкой integrity/FK/version; DB/WAL не копируются как несогласованная пара. На новой установке создаются свежие Gate signer, host binding, epoch и пустой Broker receipt journal. Не выполняются source Compose, paths, old signer, permits или receipts. DEK открывается только из нового host-bound OS wrap и сразу повторно запечатывается для установленного Broker; plaintext DEK/identity file не создаётся. AAD/ACL numeric consumers и REVOKED состояния сохраняются без расширения прав. Из App DB повторно удаляются sessions/reauth/bootstrap, старые permits/claims очищаются, в Audit/Outbox добавляется `recovery.installed`.

## Запуск

Установщик создаёт новые текущие config/Compose/systemd files, назначает API/App-group и Broker ownership и запускает системные Broker/supervisor и изолированные API/Worker containers из проверенного image. Backup target выключен до нового локального provisioning. Первичный Owner bootstrap не открывается: используется восстановленный Owner.

Пример после завершённого [Rescue import](stage1-rescue.md), с independently delivered release trust anchor:

```sh
sudo python3.15 deploy/installer.py install \
  --bundle /trusted/hostorbit-bundle \
  --trust-key /trusted/release.pub \
  --development --origin https://hostorbit.example \
  --recovery-state /var/lib/hostorbit-rescue/request-1 \
  --check
```

Для самой установки используют ту же команду без `--check`. Existing-installation checks одинаковы для fresh/recovery; они не меняют владельцев чужих каталогов и не удаляют данные. Только CI fixture имеет отдельную явную процедуру удаления принадлежащей ему тестовой установки.

Root-owned persistent writer profile остаётся `READ_ONLY_RECOVERY` при запуске, потере заменяемого latch и restart. API разрешает Auth и чтение Audit; business writes и новые jobs получают `WRITER_ADMISSION_CLOSED`. Worker остаётся живым, но не вызывает startup reconciliation или claim и корректно обрабатывает SIGTERM. Это также позволяет оставить историческую App schema 1 для Auth/Audit без скрытой DDL migration; schema-2 queue endpoints при schema 1 по-прежнему недоступны. Authority не выдаёт и не consumes permits при `activated=0`.

Возвращается `recovery=READ_ONLY_RECOVERY`, `owner_setup=RESTORED_OWNER`. Эти поля не означают active Controller, manual fencing/rotation, restore attestation или Backup Gate. [Локальная Owner activation](stage1-recovery-activation.md) требует отдельного подтверждения изоляции/ротации/quarantine. Независимый DR, ручная приёмка и signed Rescue kit остаются открытыми. Stage1/MVP acceptance не повышается автоматически.

## Evidence

Unit tests покрывают completed/consumed/incomplete ledger, active authority, изменённый receipt/pin, недоступную host credential, corruption Vault и отсутствие Worker reconciliation/claim в read-only mode. Signed-installation CI сохраняет отдельно импортированный layout, останавливает и удаляет **только собственную** исходную installation на disposable VM и устанавливает новый signed Controller из этого layout. Проверяются настоящие HTTPS Owner login/Audit, отказ users/job mutations, стабильный idle Worker, работающие без error restarts Broker/supervisor, новые inactive journals, AEAD восстановленных Vault objects с установленной OS credential и правильным Broker ownership, restart/latch-loss и отказ повторной установки. Исходные installation DB/keys/code удалены; host OS, systemd credential master и физическая VM остаются общими. Поэтому это проверка service integration, а не доказательство независимой физической аварийной площадки или ручная restore attestation.
