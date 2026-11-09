# Документация HostOrbit

Текущий статус проекта находится в [README](../README.md), рабочий процесс — в [CONTRIBUTING](../CONTRIBUTING.md).

## Структура репозитория

### Приложение и развёртывание

- [hostorbit/](../hostorbit/) — API, Auth, RBAC, SQLite, очередь и Worker; `hostorbit/runtime/` — Broker, SSH, backup и recovery.
- [web/](../web/) — интерфейс, его сборка и браузерные тесты.
- [deploy/](../deploy/) — подписанные bundles, установщик и службы systemd.
- [remote/](../remote/) — ограниченные SSH gateway/helper для управляемых серверов.

### Проверки и инструменты

- [tests_app/](../tests_app/) — прикладные проверки API, авторизации, базы и очереди.
- [tests_runtime/](../tests_runtime/) — проверки runtime и интеграционные стенды в `lab/`.
- [stage0/](../stage0/) и [tests/](../tests/) — лабораторные прототипы Stage0 и их действующие регрессионные проверки; `tests/lab/` содержит стенды.
- [tools/](../tools/) и [tests_tools/](../tests_tools/) — проверки репозитория и инструменты обслуживания с тестами.
- [.github/workflows/](../.github/workflows/) — автоматические проверки и обслуживание веток.

### История и локальные файлы

- [evidence/](../evidence/) — принятые решения, отчёты и контрольные суммы проверенных ревизий. Реестр требований и Stage0 используются текущим CI; не удаляйте их как временные данные.
- `__pycache__/`, `.ruff_cache/` и `web/test-results/` — восстанавливаемые кэши и результаты локальных проверок. `.venv/` и `web/node_modules/` содержат установленные зависимости, а `web/dist/` — сборку интерфейса; они не входят в Git, но могут использоваться локально.

## Controller и развёртывание

- [Stage2: API инвентаря VPS и достоверные наблюдения](stage2-inventory.md)
- [Stage2: сборка и запуск WebUI](../web/README.md)
- [Foundation: Owner, Auth/RBAC и хранилище](stage1-foundation.md)
- [Runtime: Worker, Broker, SSH и host authority](stage1-runtime.md)
- [Подписанная установка](stage1-installation.md)
- [Репетиция миграции БД](stage1-migrations.md)
- [Host TimeHealth](stage1-time-health.md)

## Резервное копирование и восстановление

- [Барьер записи](stage1-backup-barrier.md) и [Vault pin](stage1-vault-pins.md)
- [Подписанный Controller archive](stage1-controller-archive.md)
- [SFTP publication](stage1-sftp-publication.md)
- [Offline Rescue и импорт](stage1-rescue.md)
- [Установка восстановленного Controller](stage1-recovery-installation.md)
- [Локальная Owner activation и quarantine](stage1-recovery-activation.md)

## Требования и приёмка

- [Лаборатория Stage0](stage0-laboratory.md)
- [ADR-0001: этап AC-28](adr/0001-registry-ac28-stage.md)
- [Приёмка Stage0](../evidence/acceptance/stage0-2026-11-07/README.md)
- [Приёмка Stage1 Foundation](../evidence/acceptance/stage1-2026-11-08/README.md)

Датированные evidence описывают конкретную проверенную ревизию; их старые counts, digests и ограничения сохраняют исторический смысл. Они не служат инструкцией по установке текущего кода. Черновые материалы до приёмки доступны в истории Git.
