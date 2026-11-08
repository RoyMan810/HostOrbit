# Документация HostOrbit

Текущий статус проекта находится в [README](../README.md), рабочий процесс — в [CONTRIBUTING](../CONTRIBUTING.md).

## Структура

- `hostorbit/` — Controller API, Auth, RBAC, SQLite, очередь, Worker и runtime.
- `deploy/` — подписанные bundles, установщик, systemd и Compose profiles.
- `remote/` — ограниченные SSH gateway/helper.
- `stage0/` и `tests/` — принятые лабораторные прототипы и их регрессия.
- `tests_app/`, `tests_runtime/` — прикладные проверки и native integration fixtures.
- `tools/`, `tests_tools/` — проверки репозитория и обслуживание веток.
- `evidence/` — принятые решения, отчёты и контрольные суммы проверенных ревизий.

## Controller и развёртывание

- [Stage2: API инвентаря VPS и достоверные наблюдения](stage2-inventory.md)
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
