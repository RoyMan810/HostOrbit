# HostOrbit

Self-hosted система управления Linux-серверами по ТЗ v2.3. Прикладной Controller включает локальное создание Owner, Auth/RBAC, SQLite с Audit/Outbox, изолированные Worker/Broker, SSH observation, резервное копирование и восстановление.

## Текущее состояние

[Stage0 принят](evidence/acceptance/stage0-2026-11-07/README.md): 15 обязательных критериев. [Stage1 Foundation принят](evidence/acceptance/stage1-2026-11-08/README.md): шесть возможностей gate §40 с положительными и отрицательными проверками.

Доступна подписанная development-установка на Ubuntu 24.04 amd64. Единственный включённый remote adapter — read-only `host.probe`. Stage2, production mutations, A/B updates, live migration и независимая DR-приёмка остаются открытыми. Остальные 69 полных AC сохраняют `NOT_RUN`; Foundation не заменяет приёмку MVP.

## Работа с проектом

- [Документация и структура](docs/README.md)
- [Настройка среды, тесты и правила PR](CONTRIBUTING.md)
- [Подписанная установка](docs/stage1-installation.md)
- [Восстановление](docs/stage1-rescue.md) и [локальная активация](docs/stage1-recovery-activation.md)

Для разработки нужны Linux, Python 3.13 с SQLite ≥3.45 и закреплённые `age`/`age-keygen` v1.3.2 для crypto tests.

```sh
python3.13 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt -r requirements-quality.txt
.venv/bin/python -m pip install --no-deps -e .
.venv/bin/ruff check .
.venv/bin/python tools/check_repository.py
.venv/bin/python -m unittest discover -s tests_tools -v
```

Команды остальных test suites и native CI приведены в CONTRIBUTING. Изменения проходят PR и CI; принятые evidence хранятся отдельно от текущих эксплуатационных инструкций.
