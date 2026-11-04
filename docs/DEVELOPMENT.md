# Разработка, тестирование и сборка

**Источник правды — отдельные файлы** `install.sh`, `lib/`, `monitor-kit/`. Файл `kvpn-install.sh` — автоматически сгенерированный **самораспаковывающийся** установщик для скачивания по одному URL. Редактировать его вручную **нельзя**.

## После изменения runtime-кода

```bash
python3 tools/build_bundle.py
python3 tools/build_bundle.py --check
bash -n install.sh kvpn-install.sh lib/*.sh monitor-kit/install.sh monitor-kit/lib/*.sh
python3 -m py_compile monitor-kit/lib/*.py
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
