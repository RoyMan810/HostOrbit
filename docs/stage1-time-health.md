# Время хоста и допуск к изменениям

Host supervisor проверяет время независимо от заменяемых API/Worker. Поддержаны системные chrony 4.5 и timesyncd 255 на Ubuntu 24.04. Данные не принимаются из HTTP, application SQLite, environment Worker или произвольного JSON. Backend не получает privilege socket; Worker получает подписанный ответ через AF_UNIX с проверкой UID сервера и Ed25519 public key.

`hostorbit/runtime/clock.py` использует только фиксированные команды мониторинга. Для chrony выбрана одна локальная Unix socket `/run/chrony/chronyd.sock`, без UDP/DNS fallback. Владелец и защита каталога проверяются supervisor; тип и точный UID socket — фиксированным stdlib-helper уже после смены UID. Для него нужен системный `/usr/bin/python3` Ubuntu. PID 1 запускает короткий sandboxed `chronyc -n -c -h … tracking` от UID владельца закрытого каталога: клиенту chrony нужен собственный reply socket в том же каталоге. Supervisor сохраняет пустой capability set и не получает доступа к приватным данным Broker/Vault. Worker не выбирает executable, UID, unit properties, адрес или команду.

Для timesyncd читаются типизированный D-Bus `NTPMessage`, frequency и kernel synchronization status. Используются реальные timestamps, root delay/dispersion, precision, delay и jitter принятого пакета. Настроенный `RootDistanceMaxUSec` не выдаётся за измеренную погрешность. Если обе службы активны, источник неоднозначен и изменения запрещены. Отсутствие службы/интерфейса, неизвестный формат, local-only reference chrony, unsynchronized/leap status, spike и недопустимые значения не становятся успешной выборкой. Код не перенастраивает NTP и не устанавливает системные часы.

## Freshness и holdover

Supervisor опрашивает источник примерно раз в 30 секунд, включая idle и постоянный поток RPC. До любого допуска дополнительно проверяются host boot ID и непрерывность часов. Для известной хорошей выборки соблюдаются ограничения §36.2: age ≤300 секунд для `FRESH`, последняя синхронизация ≤24 часов, сумма absolute offset и погрешности ≤2000 ms. Старт без собственной истории более консервативен: нужен независимый пакет не старше 300 секунд.

Повтор чтения того же packet/reference ID не обновляет время синхронизации. После 300 секунд допускается `HOLDOVER` до 3600 секунд от последней годной независимой выборки. Погрешность растёт по monotonic elapsed time с drift bound не меньше 500 ppm; reported frequency/skew могут увеличить эту оценку. Изменения разрешаются только пока итоговая uncertainty ≤2000 ms. Бюджет не продлевается повторными запросами, перезапуском приложения или успешным чтением старых данных daemon.

Пропавшая telemetry может использовать уже проверенную ограниченную историю. Явно недостоверный/несинхронизированный источник, чрезмерная погрешность, смена boot ID, регресс monotonic clock или suspend разрывают доверие. После потери continuity требуется новая независимая выборка; прежний пакет не активирует старые разрешения. При неизвестных данных ответ содержит `UNTRUSTED`, причину и nullable измерения; это не утверждение о точном UTC.

Кроме сравнения realtime с `CLOCK_BOOTTIME`/monotonic, используется Linux timerfd `CANCEL_ON_SET`. Он замечает и скачок вперёд с последующим возвратом между опросами. Реализация консервативно отзывает baselines при любом kernel cancellation, даже если скачок меньше нормативного порога 1 секунды. Недоступный watcher закрывает mutating admission. Тайм-ауты, возраст и expiry привязок считаются по monotonic clock, не по изменяемому UTC.

## Привязка к плану и gate

`time.health` принимает пустой payload и возвращает подписанные claims с `source`, `last_sync_utc`, `offset_ms`, `max_error_ms`, `clock_step_detected`, `sample_age_s`, `boot_id`, состоянием и generation. Ответ дополнительно связан с authority instance, gate epoch/state и моментом наблюдения. Worker проверяет его через `verify_host_time`; наличие подписи не делает старый сохранённый report самостоятельным правом на Apply.

`time.anchor` принимает только `plan_id` и `revision`. В защищённом host journal на эту пару создаётся ровно одна time baseline с nonce, generation, boot ID и monotonic timestamp. В текущей реализации до execution claim она действует не более 15 минут. Истёкшая/отозванная baseline не заменяется новой для той же ревизии: нужен новый preflight/revision, как требует модель плана. Будущий Change Plan/approval manager должен включить этот anchor в неизменяемое содержимое плана до одобрения.

Mutating `permit.admit` требует `time_anchor` и перепроверяет его независимо от Backend. Broker consumption повторяет проверку до dispatch. Отозванный anchor не освобождает reservation автоматически: для неиспользованного permit нужен доказанный pre-dispatch cancel. Read-only `host.probe` не требует TimeHealth и сохраняет прежний контракт.

Root-only `update.quiesce` дополнительно получает `plan_id`, `revision`, `time_anchor`. Переход в maintenance и последующие переходы сверяют clock generation/continuity; уже принятое execution не получает заново approval из-за длительности работы. Потеря доверенного времени в `QUIESCING`, `MAINTENANCE` или `RESUMING` долговечно переводит gate в `RECOVERY_HOLD` с новым epoch. Отказ отправляется **после commit**, иначе exception мог бы откатить сам hold. Periodic host check действует и без нового запроса updater. Возврата из hold флагом force или восстановлением NTP нет.

## Хранение и локальная диагностика

Private journal `/var/lib/hostorbit/control-gate/time-health/time.sqlite3` отделён от мигрируемой application DB. Directory mode — `0700`, файл — `0600`, WAL/FULL/foreign keys проверяются. Journal не содержит DEK, passwords или содержимого managed VPS. API/Worker его не монтируют. Worker получает только root-owned public verification key, который не даёт права выпускать permits.

Свежая установка явно создаёт journal вместе с authority. При каждом старте supervisor повышает time generation до обслуживания IPC: старые approvals не переживают смену процесса. Если recovery journal не удалось записать, весь сеанс остаётся `UNTRUSTED`; последующее исправление диска не включает прежние baselines незаметно.

Локальная проверка установленного экземпляра:

```bash
sudo /opt/hostorbit/venv/bin/hostorbit-runtime \
  --config /etc/hostorbit/runtime.json time-health
```

Для более ранней installation, в которой journal ещё отсутствует, предусмотрено отдельное root-действие:

```bash
sudo /opt/hostorbit/venv/bin/hostorbit-runtime \
  --config /etc/hostorbit/runtime.json initialize-time-health
sudo systemctl restart hostorbit-supervisor.service
```

Инициализация отказывается заменять существующие данные. Restart инвалидирует прежние permits, а открытый update/incident может сохранить `RECOVERY_HOLD`; команда не является обходом recovery workflow. Если journal существовал и пропал/повреждён, его нельзя считать новой установкой: требуется отдельное расследование, а не удаление и re-init.

## Проверки и границы

Contract tests проверяют freshness, drift, часы назад/вперёд, net-zero step, suspend, boot, отсутствие watcher/state, сохранение failure fencing, immutability/expiry anchor, replay другой ревизии, подпись и hold после ошибки. Два отдельных disposable Ubuntu jobs используют настоящие chrony/timesyncd, локальный NTP protocol fixture, потерю NTP-ответов, systemd sandbox с пустыми capabilities, разные UID и реальный `clock_settime` вперёд/назад. Часы возвращаются до сетевого/IPC взаимодействия; этот код находится только в guarded VM lab. Installation job проверяет подписанный report внутри Worker с `network_mode: none`.

NTP fixture не является независимым UTC reference и не удостоверяет физическую точность часов. Работа механизма предполагает корректность доверенных host time daemon/configuration и выбранных ими источников; скомпрометированный root или намеренно ложный time source не превращается в достоверное время благодаря подписи supervisor.

Production mutating adapters остаются отключены. Этот блок не заменяет Owner approval manager, согласованную off-host ControllerBackup, restore attestation или применение schema migration. Stage1 и MVP gate не получают PASS только из-за добавления TimeHealth.

Форматы проверены по [chronyc 4.5](https://chrony-project.org/doc/4.5/chronyc.html), [chronyd 4.5](https://chrony-project.org/doc/4.5/chronyd.html), [systemd 255 NTPMessage](https://github.com/systemd/systemd/blob/v255/src/timesync/timesyncd-bus.c) и [обработке timestamps systemd](https://github.com/systemd/systemd/blob/v255/src/timesync/timesyncd-manager.c).
