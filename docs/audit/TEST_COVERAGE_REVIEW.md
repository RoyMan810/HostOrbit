# Проверка тестирования

## Фактически выполнено

См. среду, количество, первоначальные ошибки и итоговые результаты в [AUDIT_REPORT](AUDIT_REPORT.md#фактические-проверки). После установки проверенного age прошли 73 Stage0, 75 app, 157 runtime и 17 tools tests; после установки Chromium — 18 Playwright. Frontend build, Ruff и проверка ссылок/pins прошли. Локальная версия Python — 3.14.4, а не требуемая проектом 3.13: это дополнительная, не замещающая CI-проверка.

Stage0 gate прошёл; Stage1 gate на текущем SHA не прошёл (AUD-01); Stage2 и Stage3 закономерно заблокированы незавершёнными AC. На GitHub для текущего SHA есть прошедшие реальные boundary/installation jobs, но workflow целиком завершился failure. Проверка run metadata не заменяет повторение VM-тестов.

## Риски пробелов

| Сценарий | Что проверено / пробел | Нужная проверка |
|---|---|---|
| Архив у верхней границы | Отдельные лимиты есть, но producer и consumer расходятся (AUD-02) | Настоящий signed round-trip ниже/выше 512 MiB, tar/age overhead, несколько БД и Vault; не только mock. |
| Recovery → Job timeline | Реальный quarantine UPDATE воспроизведён в временной БД, Timeline вернул 503 (AUD-04) | Полный Rescue import, queued и dispatched job, replay цепочки и restart. |
| Release source | Отсутствие проверки untracked подтверждено; wheel не собран в данном окружении (AUD-03) | Python 3.13, untracked module, проверка точного состава wheel и заранее закреплённых hashes. |
| Низкая скорость SFTP | Математически недостаточный общий timeout (AUD-05), сетевой сценарий не выполнялся | Реальный throttled SFTP, readback, revoke, partial и retry. |
| Накопленная история | План SQLite подтверждает сортировки (AUD-06), timings не измерены | Нормативный 30-дневный dataset/8-часовой soak §37 на Ubuntu/2 vCPU/4 GiB; latency, BUSY, fsync, WAL, диск. |
| Stage2 vertical slice | AC-28 и AC-B05 — NOT_RUN | Полный VPS → Docker/Nginx → approved plan → backup → безопасный apply/verify/audit только в disposable стенде. |
| Независимое DR | Есть исторические lab/evidence, новое независимое восстановление не выполнялось | Другая машина и OS key, off-host копия, ручной протокол изоляции и restore attestation. |
| UI accessibility | Есть keyboard/mobile сценарий; 18 Chromium тестов прошли | Screen reader, фокус при смене views, автоматизированный accessibility audit, Firefox/WebKit и реальный TLS proxy. |
| Security | Unit negative tests и исторические native jobs; полный adversarial аудит не проводился | Межпроцессные UID, RBAC revoke races, malformed protocol, supply chain и secret redaction. |

## Не выдавать за доказательство

- Успешные тесты на mock/fake SFTP не подтверждают поведение сервера при реальном fsync или обрыве сети.
- Успешный `healthz` — liveness API, не readiness Broker, SSH, backup или восстановления.
- Подписанный локальный архив не равен off-host backup и не равен ручному restore attestation.
- Исторический PASS Stage0 относится к определённому прототипу и ревизии, а не автоматически ко всем будущим изменениям.
- Количество тестов или coverage процентов без assertion на failure mode не доказывает безопасность.

Не проводилась систематическая оценка flaky-тестов и дублирующих assertions каждого файла. Удаление тестов по сходству названий не рекомендуется.

## Инвентарь 84 AC в снимке реестра

Это исторические статусы и пути реестра, не заявка о выполнении каждого теста в этом аудите. Отсутствующий путь при NOT_RUN не означает поломку Stage0. Перекрёстные ссылки на требования приведены в общей матрице; ручное соответствие всех AC к текущим тест-функциям не завершено.

| AC | Этап | Статус в снимке | Историческое свидетельство |
|---|---|---|---|
| AC-01 | Stage1 | NOT_RUN | `evidence/tests/ac-01.json` — отсутствует |
| AC-02 | Stage1 | NOT_RUN | `evidence/tests/ac-02.json` — отсутствует |
| AC-03 | Stage1 | NOT_RUN | `evidence/tests/ac-03.json` — отсутствует |
| AC-04 | Stage1 | NOT_RUN | `evidence/tests/ac-04.json` — отсутствует |
| AC-05 | Stage0 | NOT_RUN | `evidence/tests/ac-05.json` — отсутствует |
| AC-06 | Stage1 | NOT_RUN | `evidence/tests/ac-06.json` — отсутствует |
| AC-07 | Stage0 | NOT_RUN | `evidence/tests/ac-07.json` — отсутствует |
| AC-08 | Stage0 | NOT_RUN | `evidence/tests/ac-08.json` — отсутствует |
| AC-09 | Stage1 | NOT_RUN | `evidence/tests/ac-09.json` — отсутствует |
| AC-10 | Stage2 | NOT_RUN | `evidence/tests/ac-10.json` — отсутствует |
| AC-11 | Stage0 | NOT_RUN | `evidence/tests/ac-11.json` — отсутствует |
| AC-12 | Stage0 | NOT_RUN | `evidence/tests/ac-12.json` — отсутствует |
| AC-13 | Stage0 | NOT_RUN | `evidence/tests/ac-13.json` — отсутствует |
| AC-14 | Stage1 | NOT_RUN | `evidence/tests/ac-14.json` — отсутствует |
| AC-15 | Stage2 | NOT_RUN | `evidence/tests/ac-15.json` — отсутствует |
| AC-16 | Stage1 | NOT_RUN | `evidence/tests/ac-16.json` — отсутствует |
| AC-17 | Stage2 | NOT_RUN | `evidence/tests/ac-17.json` — отсутствует |
| AC-18 | Stage1 | NOT_RUN | `evidence/tests/ac-18.json` — отсутствует |
| AC-19 | Stage4 | NOT_RUN | `evidence/tests/ac-19.json` — отсутствует |
| AC-20 | Stage4 | NOT_RUN | `evidence/tests/ac-20.json` — отсутствует |
| AC-21 | Stage2 | NOT_RUN | `evidence/tests/ac-21.json` — отсутствует |
| AC-22 | Stage1 | NOT_RUN | `evidence/tests/ac-22.json` — отсутствует |
| AC-23 | Stage4 | NOT_RUN | `evidence/tests/ac-23.json` — отсутствует |
| AC-24 | Stage4 | NOT_RUN | `evidence/tests/ac-24.json` — отсутствует |
| AC-25 | Stage4 | NOT_RUN | `evidence/tests/ac-25.json` — отсутствует |
| AC-26 | Stage2 | NOT_RUN | `evidence/tests/ac-26.json` — отсутствует |
| AC-27 | Stage4 | NOT_RUN | `evidence/tests/ac-27.json` — отсутствует |
| AC-28 | Stage2 | NOT_RUN | `evidence/tests/ac-28.json` — отсутствует |
| AC-29 | Stage2 | NOT_RUN | `evidence/tests/ac-29.json` — отсутствует |
| AC-30 | Stage4 | NOT_RUN | `evidence/tests/ac-30.json` — отсутствует |
| AC-31 | Stage4 | NOT_RUN | `evidence/tests/ac-31.json` — отсутствует |
| AC-32 | Stage1 | NOT_RUN | `evidence/tests/ac-32.json` — отсутствует |
| AC-33 | Stage1 | NOT_RUN | `evidence/tests/ac-33.json` — отсутствует |
| AC-34 | Stage2 | NOT_RUN | `evidence/tests/ac-34.json` — отсутствует |
| AC-35 | Stage1 | NOT_RUN | `evidence/tests/ac-35.json` — отсутствует |
| AC-36 | Stage2 | NOT_RUN | `evidence/tests/ac-36.json` — отсутствует |
| AC-37 | Stage1 | NOT_RUN | `evidence/tests/ac-37.json` — отсутствует |
| AC-38 | Stage1 | NOT_RUN | `evidence/tests/ac-38.json` — отсутствует |
| AC-39 | Stage1 | NOT_RUN | `evidence/tests/ac-39.json` — отсутствует |
| AC-40 | Stage0 | NOT_RUN | `evidence/tests/ac-40.json` — отсутствует |
| AC-41 | Stage1 | NOT_RUN | `evidence/tests/ac-41.json` — отсутствует |
| AC-42 | Stage1 | NOT_RUN | `evidence/tests/ac-42.json` — отсутствует |
| AC-43 | Stage2 | NOT_RUN | `evidence/tests/ac-43.json` — отсутствует |
| AC-44 | Stage1 | NOT_RUN | `evidence/tests/ac-44.json` — отсутствует |
| AC-45 | Stage1 | NOT_RUN | `evidence/tests/ac-45.json` — отсутствует |
| AC-46 | Stage0 | NOT_RUN | `evidence/tests/ac-46.json` — отсутствует |
| AC-47 | Stage1 | NOT_RUN | `evidence/tests/ac-47.json` — отсутствует |
| AC-48 | Stage1 | NOT_RUN | `evidence/tests/ac-48.json` — отсутствует |
| AC-49 | Stage1 | NOT_RUN | `evidence/tests/ac-49.json` — отсутствует |
| AC-50 | Stage1 | NOT_RUN | `evidence/tests/ac-50.json` — отсутствует |
| AC-51 | Stage1 | NOT_RUN | `evidence/tests/ac-51.json` — отсутствует |
| AC-52 | Stage1 | NOT_RUN | `evidence/tests/ac-52.json` — отсутствует |
| AC-A01 | Stage0 | PASS | [evidence/tests/ac-a01.json](../../evidence/tests/ac-a01.json) |
| AC-A02 | Stage0 | PASS | [evidence/tests/ac-a02.json](../../evidence/tests/ac-a02.json) |
| AC-A03 | Stage0 | PASS | [evidence/tests/ac-a03.json](../../evidence/tests/ac-a03.json) |
| AC-A04 | Stage0 | PASS | [evidence/tests/ac-a04.json](../../evidence/tests/ac-a04.json) |
| AC-A05 | Stage0 | PASS | [evidence/tests/ac-a05.json](../../evidence/tests/ac-a05.json) |
| AC-A06 | Stage1 | NOT_RUN | `evidence/tests/ac-a06.json` — отсутствует |
| AC-A07 | Stage1 | NOT_RUN | `evidence/tests/ac-a07.json` — отсутствует |
| AC-A08 | Stage0 | NOT_RUN | `evidence/tests/ac-a08.json` — отсутствует |
| AC-A09 | Stage1 | NOT_RUN | `evidence/tests/ac-a09.json` — отсутствует |
| AC-A10 | Stage0 | NOT_RUN | `evidence/tests/ac-a10.json` — отсутствует |
| AC-A11 | Stage2 | NOT_RUN | `evidence/tests/ac-a11.json` — отсутствует |
| AC-A12 | Stage2 | NOT_RUN | `evidence/tests/ac-a12.json` — отсутствует |
| AC-A13 | Stage2 | NOT_RUN | `evidence/tests/ac-a13.json` — отсутствует |
| AC-A14 | Stage1 | NOT_RUN | `evidence/tests/ac-a14.json` — отсутствует |
| AC-A15 | Stage1 | NOT_RUN | `evidence/tests/ac-a15.json` — отсутствует |
| AC-A16 | Stage0 | NOT_RUN | `evidence/tests/ac-a16.json` — отсутствует |
| AC-A17 | Stage1 | NOT_RUN | `evidence/tests/ac-a17.json` — отсутствует |
| AC-A18 | Stage1 | NOT_RUN | `evidence/tests/ac-a18.json` — отсутствует |
| AC-A19 | Stage0 | NOT_RUN | `evidence/tests/ac-a19.json` — отсутствует |
| AC-A20 | Stage0 | PASS | [evidence/tests/ac-a20.json](../../evidence/tests/ac-a20.json) |
| AC-A21 | Stage1 | NOT_RUN | `evidence/tests/ac-a21.json` — отсутствует |
| AC-A22 | Stage2 | NOT_RUN | `evidence/tests/ac-a22.json` — отсутствует |
| AC-B01 | Stage0 | PASS | [evidence/tests/ac-b01.json](../../evidence/tests/ac-b01.json) |
| AC-B02 | Stage0 | PASS | [evidence/tests/ac-b02.json](../../evidence/tests/ac-b02.json) |
| AC-B03 | Stage0 | PASS | [evidence/tests/ac-b03.json](../../evidence/tests/ac-b03.json) |
| AC-B04 | Stage0 | PASS | [evidence/tests/ac-b04.json](../../evidence/tests/ac-b04.json) |
| AC-B05 | Stage2 | NOT_RUN | `evidence/tests/ac-b05.json` — отсутствует |
| AC-B06 | Stage0 | PASS | [evidence/tests/ac-b06.json](../../evidence/tests/ac-b06.json) |
| AC-B07 | Stage0 | PASS | [evidence/tests/ac-b07.json](../../evidence/tests/ac-b07.json) |
| AC-B08 | Stage0 | PASS | [evidence/tests/ac-b08.json](../../evidence/tests/ac-b08.json) |
| AC-B09 | Stage0 | PASS | [evidence/tests/ac-b09.json](../../evidence/tests/ac-b09.json) |
| AC-B10 | Stage0 | PASS | [evidence/tests/ac-b10.json](../../evidence/tests/ac-b10.json) |
