# Барьер записи перед согласованным Controller snapshot

Это прикладная основа Coordinator из §33.1 ТЗ v2.3. Новая установка включает её для API, Worker, Broker, Vault и host authority. Сам барьер не открывает Backup Gate: создание локального age archive/signature описано отдельно, off-host publication и проверка восстановления остаются следующими gates.

[Локальный Vault pin](stage1-vault-pins.md) захватывает private Vault/receipt SQLite и referenced ciphertext отдельным sandboxed Broker helper.

[Controller archive](stage1-controller-archive.md) использует barrier для полного поддержанного data snapshot; после освобождения writer lock выполняет age key export и `SEALED → SIGNED`. Off-host completion и Backup Gate остаются следующими gates.

## Контракт записи

Root владеет постоянным inode `writers.lock` и атомарно заменяемым `state.json` в `/var/lib/hostorbit/writer-admission` (каталог 0755, файлы 0644, без symlink/hardlink). API и Worker получают только read-only bind всего каталога, поэтому видят новые состояния после rename, но не могут заменить lock или latch. Отдельный private control journal находится в `/var/lib/hostorbit/control-gate/snapshots` (0700/0600).

Каждый поддержанный SQLite writer получает shared kernel flock **до** открытия транзакции и держит его до commit/rollback. В режиме `CLOSING_ADMISSION`:

- `business` закрывает создание пользователей, изменение ролей/прав, bootstrap, регистрацию ресурсов, enqueue Job, import/revoke Vault и начало maintenance;
- `dispatch` закрывает новые claims Worker и выдачу новых GatePermit, включая read-only Job;
- `control` сохраняет login/logout, session/rate-limit/reauth metadata, Audit/Outbox этих операций, переходы и завершение ранее принятых Job, consume/ACK/cancel/receipts и продолжение уже начатого maintenance.

В `SHORT_BARRIER` все эти snapshot-critical writers ждут завершения exclusive flock. Ожидание не удерживает SQLite write transaction. Новые claims при закрытом приёме не завершают Worker аварийно: процесс продолжает ожидать. В API новый Job получает HTTP 503 с `Retry-After: 1`. GET с обновлением session/rate-limit metadata работает при drain и может кратко ждать во время самого снимка.

Private TimeHealth journal и journal самого Coordinator остаются независимыми control metadata. Supervisor продолжает наблюдение clock continuity; snapshot не выполняет RPC к supervisor из-под exclusive lock.

## Фазы и отказ

`Coordinator.snapshot()` принимает только доверенные host-side callbacks: короткий poll активной работы и локальное копирование/pin/fsync. Нового Web/Worker RPC или generic privileged subprocess API не добавлено.

Приём закрывается durable latch до первого control commit. Фазы `REQUESTED → CLOSING_ADMISSION → SHORT_BARRIER → BARRIER_RELEASED` фиксируются отдельными SQLite commits и append-only transition log с boot ID и monotonic time. Drain ограничен 60 секундами, локальный барьер — 30 секундами; CLI использует interrupting POSIX timer, а не только проверку времени после callback. Вызов допустим в главном потоке без другого активного `ITIMER_REAL`. Шифрование, подпись, сеть и ожидание удалённых эффектов должны выполняться после возврата из barrier primitive.

Python обрабатывает сигнал в главном потоке между исполняемыми инструкциями; длительный C extension или непрерываемый kernel I/O нельзя автоматически ограничить этим таймером. Поэтому будущий production capture обязан разбивать копирование на ограниченные шаги с progress/deadline либо использовать завершаемые дочерние процессы. Этот primitive не является доказательством временной границы для произвольного callback.

На timeout/ошибке снимается exclusive lock, состояние `RECOVERY_HOLD` допускает control writes, затем записывается `ABORTED` и только после commit открывается business admission. Если commit недоступен, приём остаётся закрытым. Ошибка публикации latch удаляет прежний OPEN state: отсутствие/повреждение state запрещает writer, а не включает fallback. Восстановление отсутствующего state возможно только Root Coordinator после проверки доступного собственного журнала; повреждённые permissions/формат автоматически не исправляются.

SIGKILL не снимает durable latch, хотя kernel освобождает flock. Root supervisor проверяет закрытый latch при IPC и периодическом poll, получает lifetime lock Coordinator без ожидания и восстанавливает только погибший процесс. Пока Coordinator жив, его lock не даёт watchdog открыть приём. Прерванный локальный снимок получает `ABORTED`, включая остановку после commit `BARRIER_RELEASED`, но до открытия latch. Supervisor выполняет такую же проверку при старте. Незаписанный/прерванный снимок не объявляется опубликованным, проверенным или восстановленным.

## Проверки и границы

Unit tests используют отдельные процессы и настоящий `SIGKILL` во всех четырёх локальных фазах. Проверяются запись ACK при drain, отсутствие SQLite transaction у заблокированного writer, завершение уже активной транзакции до capture, прерывание зависшего callback, ENOSPC journal/state, rollback и отказ при подмене файлов. Runtime test завершает уже начатый SSH Job при закрытом приёме, оставляя следующий Job в очереди. API test проверяет retryable 503 без Job/Audit частичной транзакции.

Signed-installation CI проверяет код установленного wheel, фактические UID API/Worker, read-only mounts, контрольные записи при drain, остановку critical writers и восстановление после SIGKILL через независимый supervisor. Это временная GitHub-hosted Ubuntu VM; пользовательский VPS и SSH credentials не используются.

Legacy configuration без `writer_directory` сохраняет прежний development/runtime профиль и не может служить доказательством согласованного ControllerBackup. Прямой SQL в обход поддержанных Store/Journal API, изменение root-owned конфигурации и файлов администратором относятся к Root/Backend TCB из ТЗ. SQLite/lock требуют поддержанного локального POSIX filesystem; NFS не добавляется. Работающая версия Vault имеет только DEK generation 1: многопоколенная ротация и retention/pins пока не реализованы и не считаются проверенными этой работой.
