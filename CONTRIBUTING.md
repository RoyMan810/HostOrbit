# Разработка HostOrbit

## Среда

Для воспроизведения CI используйте Linux и Python 3.15.2 с SQLite ≥3.45. Создайте `.venv` и установите `requirements-dev.txt` вместе с `requirements-quality.txt`. Для crypto tests нужны `age` и `age-keygen` v1.3.2. CI сверяет SHA-256 официального архива до запуска. `age` должен быть в `PATH`. Для runtime tests задайте `HOSTORBIT_TEST_AGE_DIR` с обоими executables.

```sh
python3.15 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt -r requirements-quality.txt
.venv/bin/python -m pip install --no-deps -e .
```

Runtime dependencies закреплены в `requirements-app.txt`, лабораторные — в `requirements-lab.txt`, инструменты качества — в `requirements-quality.txt`. Согласуйте версии пересекающихся packages и direct dependencies в `pyproject.toml`. Dependabot открывает сгруппированные PR; обновление проходит те же проверки и приёмку, что и код.

## Проверки

Из корня репозитория:

```sh
.venv/bin/ruff check .
.venv/bin/python tools/check_repository.py
.venv/bin/python -m unittest discover -s tests_tools -v
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m unittest discover -s tests_app -v
.venv/bin/python -m unittest discover -s tests_runtime -v
```

Ruff проверяет синтаксис, неопределённые имена и выбранные ошибки корректности; массовое автоформатирование принятого кода не применяется. Repository checker проверяет локальные Markdown links и согласованность dependency pins. Регрессионный тест добавляется для изменения поведения или найденного дефекта; косметические правки не требуют отдельного теста.

`tests/` остаётся действующей регрессией Stage0. Прикладные suites и лаборатория проверяют разные контракты; одинаковая тема теста не означает дублирование. Удалять тест можно после проверки, что его assertion сохранился в другой исполняемой проверке и принятом evidence.

CI дополнительно запускает настоящие Linux UID, SSH, Docker, systemd/Compose и TimeHealth стенды. Отдельный workflow проверяет потерю исходной VM и перенос Vault. Native fixtures меняют окружение и запускаются только на disposable GitHub-hosted VM; `--isolated-vm` не предназначен для рабочей системы.

## Приёмка и evidence

Используйте [ТЗ v2.4](docs/spec/HostOrbit_Technical_Spec_v2.4.md) и его [реестр](docs/spec/HostOrbit_Requirements_Registry_v2.4.json). Команды запускайте из корня.

```sh
registry=docs/spec/HostOrbit_Requirements_Registry_v2.4.json
.venv/bin/python -m stage0.requirements "$registry" --gate Stage0 --evidence-root .
.venv/bin/python -m stage0.requirements "$registry" --gate Stage1 --evidence-root .
.venv/bin/python -m stage0.requirements "$registry" --gate Stage2 --evidence-root .
.venv/bin/python -m stage0.requirements "$registry" --gate Stage3 --evidence-root .
```

Stage0 и Stage1 проверяют принятую основу. Для Stage2 и Stage3 код выхода `2` перечисляет открытые критерии. Текущий CI дополнительно воспроизводит принятую базу v2.3 по историческому снимку. Смена ссылки в source-bound workflow потребует повторной валидации Foundation. Обновляйте ТЗ, реестр и связанные критерии вместе, фиксируйте решения в ADR.

Существующие отчёты приёмки описывают историческую ревизию. Изменение исходников, закреплённых в capability report, требует повторной проверки и новых evidence. Не заменяйте digest, assertions, reviewer или статус на PASS ради зелёного CI. Компонентная проверка не подменяет независимый DR или ручное свидетельство Owner.

## Ветки и PR

Основная ветка — `main`. Используйте короткоживущие `feat/…`, `fix/…`, `chore/…`, `docs/…` или `test/…`; один PR решает одну связанную задачу. В описании укажите итоговое поведение, проверки и влияние на приёмку. Изменения сливаются после успешного CI, история сохраняется squash merge.

После изменения `main` workflow Branch maintenance удаляет только временные ветки с влитым PR: вершина должна совпадать с принятой вершиной PR, merge commit должен входить в текущую историю `main`, открытых PR быть не должно. Default/protected branches исключены. Git push использует точный `--force-with-lease` для каждой удаляемой ссылки; изменение ветки после проверки прерывает весь atomic push. Новые credentials не требуются: token выдаётся только job обслуживания. Workflow исполняет код из `main` и не делает checkout головной ветки PR.

## Документация

Обновляйте существующую инструкцию вместе с изменением поведения. Текущие инструкции находятся в [docs](docs/README.md), архитектурные решения — в `docs/adr/`, принятые свидетельства — в `evidence/`. Промежуточные планы и черновые отчёты после завершения работы остаются в истории Git. Новые ключи, БД, сборки и локальные результаты тестов в коммит не включаются.
