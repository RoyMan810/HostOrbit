# Приёмка Stage0 и Stage1 Foundation

По запросу владельца выполнена повторная проверка Stage0 и приёмка **Stage1 Foundation в объёме единственного gate §40**. Решение: **Stage0 — ACCEPTED, подтверждён повторно; Stage1 Foundation — ACCEPTED**. Проверенная ревизия `688d1408004580d95ddd4d6bd1c75c576b1bb764`, дерево `0cbeffc76fb5b494db138dc6a42aec081626285f`. Полное решение и его digest — [decision.json](decision.json).

Источник критериев — сопровождающий канонический Requirements Registry v2.3 и §40 ТЗ. Нормативные критерии, assertions, stage assignments и статусы полных AC не изменялись. Это запись исполнения существующего gate, а не новый альтернативный реестр.

Stage0: все 15 обязательных reports имеют PASS и корректный evidence digest. В проверенной исходной ревизии его прототипы/старые тесты/remote helpers не изменились относительно принятой `71d964e18d7251430e0d998022f9ceb6d3bee156`; CI той ревизии проверил 66 Stage0 tests и ещё четыре SFTP publication tests. Для проверки отчётов Foundation добавлены четыре отрицательных теста: локальная regression валидатора и прототипов теперь проходит 70 тестов. Ранее принятый независимый VM-прототип восстановления сохраняет явно записанные ограничения и не подменяет production DR.

Stage1 gate определён через **шесть capabilities**, а не через прохождение всех тестов с тегом Stage1 или наличие полного UI AC-28. Для каждой сохранён отдельный отчёт в `evidence/capabilities/stage1/`, содержащий ограниченный Foundation assertion, положительные/отрицательные проверки, исходники с SHA-256, build/manifest/SBOM digests, CI jobs/excerpts/log hashes, время, reviewer и ограничения:

- `owner_auth`: local-only Owner bootstrap, Argon2id, HTTPS sessions/cookies, CSRF, rate limiting и re-auth; проверены first-visitor denial, expiry/replay/revocation и отсутствие secret input в ответах.
- `rbac`: базовые Owner/Admin/Operator/Auditor и серверные explicit scopes; проверены чужие scope, запрещённое делегирование, role/session revoke и проверка перед dispatch.
- `sqlite_audit_outbox`: WAL/FK/synchronous/permissions, Audit chain и transactional Outbox; проверены rollback, SIGKILL, tampering и отсутствие автоматического повторения UNKNOWN.
- `ssh_helper`: установленный fixed read-only probe через numeric/CIDR target, pinned host key, forced command, точечный sudo/root helper; shell/PTY/forwarding/host-key replacement/невалидный stdout отвергаются.
- `broker_ipc`: отдельные UID/GID, socket DAC/SO_PEERCRED, scoped signed one-use permits и AEAD-bound Secret Reference; API не получает sockets/Vault/DEK, spoof/replay/scope/ciphertext attacks отвергаются.
- `admission_supervisor`: независимый root host supervisor и durable journal, Worker/updater separation, maintenance/UNKNOWN holds, writer barrier и TimeHealth; включены race/crash/SIGKILL, clock-step и restart negatives.

Проверен [успешный CI непосредственно на main](https://github.com/RoyMan810/HostOrbit/actions/runs/42415508424): **9/9 jobs**, **51 application + 137 runtime tests**, отдельные реальные Linux identity, SSH namespace, Docker, systemd/Compose, chrony/timesyncd и restrictive SSH стенды. `ci-observations.json` содержит точные job IDs и SHA-256 полных decoded UTF-8 logs без изменения newline/BOM. Исторический evidence относится к указанной ревизии; валидатор Stage1 выявляет изменение проверяемых source files и требует повторной валидации evidence.

`source-manifest.json` фиксирует 122 checked-source/dependency/workflow files. Build digest вычислен SHA-256 списка отсортированных records в UTF-8 JSON с indent=2, sort_keys и final newline. `sbom.cdx.json` ограничен закреплёнными app dependencies, age и OCI identities из workflow; это не полный OS/image SBOM или production release manifest. `baseline-check.json` подтверждает нормативный индекс и трассу реестра.

## Граница приёмки

**Не приняты автоматически:** все полные требования с `stage=Stage1`, все 34 полных AC с этим тегом, Stage2, Stage3/MVP, независимый production DR, genuine human fencing/rotation, A/B update/self-update/live DDL apply, DEK lifecycle, Global→Group→VPS Effective Policy, Scheduler, full diagnostics/privacy export, RU/EN help package и capacity/retention soak. Существующие 15 AC PASS сохранены; остальные **69 AC — NOT_RUN**, из них **61 остаётся обязательным MVP blocker**. `FR.state`/`evidence_status` не повышались. Не весь scope одного FR обязан быть готов на Foundation gate, даже если в его карточке указан Stage1.

Нативный activation fixture использует пустой inventory и симулирует Owner/local-isolation protocol на одной disposable VM. Он не доказывает real VPS rotation или независимую физическую recovery площадку. Полные capabilities/AC принимаются по их собственным assertions на последующих gates. Backend/Worker/Broker/root остаются в заявленном TCB, скрытый полный clone не распознаётся гарантированно. Рецензент — **Codex, автоматическая самопроверка кода и evidence**; независимый человеческий аудит не проводился. Владелец заранее разрешил считать этапы принятыми при успешной проверке; ручная DR attestation этим решением не создаётся.

## Воспроизводимая проверка

```sh
python -m stage0.requirements evidence/acceptance/stage0-2026-11-07/HostOrbit_Requirements_Registry_v2.3.json --gate Stage0 --evidence-root .
python -m stage0.requirements evidence/acceptance/stage0-2026-11-07/HostOrbit_Requirements_Registry_v2.3.json --gate Stage1 --evidence-root .
python -m stage0.requirements evidence/acceptance/stage0-2026-11-07/HostOrbit_Requirements_Registry_v2.3.json --gate Stage3 --evidence-root .
```

Stage0/Stage1 должны вернуть `passed` и код 0. Stage3 должен вернуть `blocked` и код 2. Stage1 reader берёт список capabilities исключительно из канонического gate; наличие green jobs без полного evidence не даёт PASS. Отрицательные тесты проверяют missing capability/evidence, отсутствие negative checks, неверный scope, изменённый код/отчёт/артефакт, path escape и невозможность повысить MVP gate через приёмку Foundation.
