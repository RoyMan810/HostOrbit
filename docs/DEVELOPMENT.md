# Разработка, тестирование и сборка

**Источник правды — отдельные файлы** `install.sh`, `lib/`, `monitor-kit/`. Файл `kvpn-install.sh` — автоматически сгенерированный **самораспаковывающийся** установщик для скачивания по одному URL. Редактировать его вручную **нельзя**.

## Версионирование

Файл [`VERSION`](../VERSION) — единый источник версии приложения в формате `MAJOR.MINOR.PATCH`. Команды `install.sh --version` и `kvpn-install.sh --version`, Textual и резервные меню показывают одно значение. Версия зависимости Textual управляется отдельно. После изменения `VERSION` обязательно пересоберите `kvpn-install.sh` через `python3 tools/build_bundle.py`, проверьте синхронность и выполните тесты ниже.

## После изменения runtime-кода

```bash
python3 tools/build_bundle.py
python3 tools/build_bundle.py --check
bash -n install.sh kvpn-install.sh lib/*.sh monitor-kit/install.sh monitor-kit/lib/*.sh
python3 -m py_compile monitor-kit/lib/*.py lib/textual_ui.py
python3 -m unittest discover -s tests -v
python3 -m unittest discover -s monitor-kit/tests -v
bash kvpn-install.sh help
```

`tools/build_bundle.py` использует только Python stdlib, стабильные timestamp/permissions и включает **только runtime-файлы**, исключая вложенную копию `kvpn-install.sh`, тесты и документацию. `--check` сигнализирует о рассинхронизации. GitHub Actions запускает тесты и проверяет синхронность на поддерживаемых образах Ubuntu.

## Риски и правила

- Нельзя тестировать команды установки на production VPS. Запуск `node`, `firewall`, `wizard`, `decoy` и реальных `monitor` изменяет систему. Нужен отдельный тестовый VPS/VM с доступом к консоли.
- Модульные тесты с моками **не доказывают** правильность firewall и VPN на всех облачных платформах.
- Никаких реальных токенов, Node compose с секретами, приватных SSH-ключей, архивов или эксплуатационных IP в Git.
- Для CI не нужна авторизация в Telegram или доступ к реальному мониторингу.
- При изменении параметров установки обновите CLI help, README, соответствующий раздел docs и тесты.

См. [SECURITY.md](../SECURITY.md).


## Разработка интерфейса Textual

Интерфейс находится в `lib/textual_ui.py` и **не содержит действий по установке**: он запускает только разрешённые CLI-команды `install.sh`. Вопросы из Bash передаются через `lib/textual_protocol.sh` по закрытому протоколу «stderr frame → stdin reply». Это позволяет сохранить старые мастера в CLI/whiptail и не записывать токен в аргументы запуска. Не включайте `set -x` / `bash -x` при работе с секретами.

Локальное тестирование **в отдельном venv**:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install 'textual==8.2.8'
.venv/bin/python -m unittest discover -s tests -v
```

`tests/test_textual_ui.py` использует headless `App.run_test()` для проверки навигации и подтверждений; остальные тесты протокола не требуют Textual. CI должен запускать UI-тест в виртуальном окружении с установленной версией библиотеки.

Не добавляйте запуск произвольных shell-команд из поля ввода: разрешённые команды перечислены в `TASKS`, а subprocess вызывается только через `create_subprocess_exec`. Изменения состояния сервера требуют явного подтверждения, затем остаются исходные подтверждения Bash-мастеров. При отмене шага отправляется специальный ответ и установка прекращается; **системные действия, выполненные до отмены, не откатываются автоматически**.
