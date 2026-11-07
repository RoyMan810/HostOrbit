# Локальная Owner activation после восстановления

`hostorbit-activate` добавляет переход установленного восстановленного Controller из READ_ONLY_RECOVERY в ACTIVE с устойчивым карантином. Это локальная административная процедура: нет Web/Worker endpoint, provider API, автоматического выключения старого хоста, SSH shell из UI или `force-active`.

## Что подтверждает Owner

Внешний ручной runbook сначала останавливает/маскирует старые Worker/Scheduler, блокирует автозапуск, прекращает опасные прямые и delegated effects либо изолирует старый хост через независимую консоль. Owner отдельно сверяет прежний Controller ID, известный SSH host fingerprint и recovery source hash. SSH timeout, DNS и одиночный скриншот не считаются fencing.

JSON report содержит `v=1`, `type=hostorbit.manual-isolation`, `source_instance`, `target_instance`, `source_backup_hash`, `dependencies_reviewed=true`, `isolation`, `targets`. В `isolation` обязательны:

- `method`: `verified_local_stop`, `power_off` или `network_isolation`;
- `console`, `operator`, `old_host_key` в OpenSSH `SHA256:…` формате;
- true для `worker_stopped`, `scheduler_stopped`, `autostart_blocked`, `old_permissions_revoked`, `dangerous_operations_stopped`;
- минимум два `observations` с разными `source`, реальными `at_utc`, `isolated=true` и интервалом ≥10 секунд, не старше суток.

Для каждой protected VPS нужен ровно один report. Недоступная цель: `reachable=false`, `evidence`. Доступная: true для `reachable`, `credentials_rotated`, `old_key_denied`, `new_key_verified`, fingerprints `old_key_sha256`/`new_key_sha256`, `evidence` и отдельные boolean `direct_stopped`, `delegated_terminal`, `postconditions_verified`. При false в effect flags цель и весь shared-dependency closure остаются в карантине. OPEN incidents из восстановленного App journal также расширяют карантин; неизвестная cross-host связь закрывает весь inventory. Они не объявляются разрешёнными/завершёнными и блокируют Controller update quiesce.

Это **доверие к компетентному Owner и конкретному runbook**, а не аппаратное доказательство выключения чужой машины. CLI проверяет структуру, binding и полноту свидетельств; он не наблюдает автоматически независимую физическую консоль. Скрытый полный clone и недостоверное утверждение Owner остаются за границей гарантии.

## Ротация credentials до активации

Старые удалённые `authorized_keys`/права удаляются, новые ограниченные ключи проверяются администратором **вне HostOrbit Jobs**. Локальная копия старого ref должна стать REVOKED. Candidate protected policy сохраняет тот же inventory, адреса, host pins, capabilities и dependency graph; для переводимых целей меняются только `secret_ref` и `policy_revision=old+1`.

Нативные Broker-UID команды `recovery-import-key` и `recovery-revoke-key` работают только при READ_ONLY_RECOVERY и под системной OS credential. Первая принимает приватный SSH import file Broker ownership/mode, существующий target, новую immutable version и policy revision; вторая отзывает только текущий protected ref указанного target. Это локальное control provisioning, не разрешение отправить SSH. Файл импорта удаляет оператор после успешного импорта. Offline Owner age identity не используется.

Внутренний `recovery-key-facts` работает без сети под тем же UID/OS credential: integrity/FK и AEAD всего Vault, public fingerprints выбранных старых/новых versions, old REVOKED/new ACTIVE, разные ключи, правильные purpose/target, новый revision и ровно UID установленного Worker. Он не возвращает secret/DEK. На import/revoke действует отдельный lifecycle lock; Root удерживает его на финальной проверке и commit. Никакой generic decrypt/export RPC не добавлен.

## Подготовка и отдельное подтверждение

`prepare` принимает завершённый исходный Rescue ledger, private JSON report, Root-protected candidate policy и **отдельно сохранённый** `--old-host-key`. Ledger/import/installation completion, source provenance/pin, current policy и исходный host wrap перепроверяются. Report fingerprint должен совпасть с независимым CLI input. Проверяются текущие App Audit/schema/Owner, отсутствие возобновлённых jobs, inactive Gate instance/epoch и Vault facts.

Пример формы команды (публичные fingerprints/пути допустимы в argv):

```sh
sudo /opt/hostorbit/venv/bin/hostorbit-activate \
  --state /var/lib/hostorbit-rescue/request-1 \
  --old-host-key SHA256:PUBLIC_SOURCE_FINGERPRINT \
  prepare --report /root/manual-isolation.json --policy /root/recovered-targets.json
```

Review возвращает plan ID, exact `confirmation_sha256`, report hash и allowed/quarantined targets. Plan живёт 900 секунд по boot-bound monotonic deadline. Команда `activate --plan-id …` с теми же global arguments требует удостоверенного локального терминала: Owner отдельно вводит полный review digest, username и скрытый password. Secrets/digest не принимаются через flags, environment, pipe или WebUI. Пять неверных password блокируют данный plan. Schema 1 остаётся read-only до отдельной разрешённой migration; скрытого DDL при activation нет.

## Устойчивый переход

Plan погашается до побочных действий; Root пишет `activation.pending`, затем останавливает **только службы нового установленного Controller**. Исходный хост программа не трогает. После lifetime locks старого supervisor и Vault, повторной проверки ключей и baseline выполняется ограниченная локальная секция с writer EX lock/30-секундным deadline: current protected policy, registered scopes/enabled flags, App Audit/Outbox, signed authorization и Gate activated/epoch/policy commits. Сеть и остановка служб находятся вне EX barrier. Trusted Python/interruptible local I/O ограничиваются timer; произвольный uninterruptible kernel I/O не считается доказанно прерываемым.

Последними публикуются Root-owned ACTIVE profile и OPEN latch, затем удаляется pending marker и запускаются Broker/supervisor/API/Worker с новой policy. Между отдельными DB/file commits pending marker сохраняет read-only даже при SIGKILL. Ошибка оставляет RECOVERY_BLOCKED и погашенный plan; частичные изменения не откатываются вслепую, автоматического resume/force-open нет. Требуется отдельный разбор/новое восстановление. ACTIVE может быть подтверждён только полным durable authorization; старые jobs, approvals, attempts и расписания не запускаются повторно.

На каждом recovered Gate use проверяются Ed25519 authorization, instance/host/policy binding и digest в protected writer profile. Потерянная/повреждённая запись закрывает business admission. И issue, и consume запрещают цели вне allowed set; App registry отключает карантинные targets. До отдельного reconciliation/release решения им не выдаются даже новые SSH probe permits. Normal reboot сохраняет законную activation, но не распознаёт скрытый clone. Поддержанным runtime adapter по-прежнему остаётся `host.probe`; activation не включает неподдержанные mutators, update/schema apply и не обходит TimeHealth/Backup Gate.

## Evidence

Unit/fault tests используют разные Ed25519 keys и проверяют false/missing isolation, source fingerprint, inventory, exact confirmation/password/lockout/expiry, изменённый epoch/ключ, AEAD-bound ACL, старый/revoked key, dependency/delegated-effect quarantine, signature corruption и отказ повторного plan. SIGKILL выполняется на CONFIRMED, SERVICES_STOPPED, POLICY_WRITTEN, APP_COMMITTED, GATE_COMMITTED и AUTHORIZED; restart/watchdog не открывает незавершённую activation.

Signed-installation CI запускает установленную local CLI через PTY с отдельным digest и скрытым password, реальным systemd Broker credential helper, остановкой/запуском служб и supervisor restart. В этом fixture inventory пуст, старую installation удалил сам disposable-VM test harness, Owner/runbook представлены явно обозначенной симуляцией. Он подтверждает установленный console/service path, **не человеческую аттестацию, real VPS credential rotation или независимый physical DR**. Эти проверки остаются отдельными; AC/Stage1/MVP, RESTORE_ATTESTED и Backup Gate автоматически не повышаются.
