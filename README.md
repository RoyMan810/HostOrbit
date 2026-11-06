# K-VPN Node Deployer

**Интерактивный установщик компонентов K-VPN для новых VPS** с Remnawave Node (Xray), UFW, Docker, HTTPS-целью для REALITY, резервным копированием и независимым Telegram-мониторингом.

**Новый интерфейс на [Textual](https://textual.textualize.io/)** — терминальная панель управления по SSH: боковая навигация по 17 операциям, сводка сервисов, мастер ввода в отдельных диалогах, скрытый ввод токена, журнал и подтверждения. `↑/↓` — выбор, `Enter` — пункт, кнопка **«Выполнить»** запускает действие, `Esc` отменяет текущий диалог, `R`/`F5` обновляет сводку, `Q` — выход. Выбор пункта **сам по себе ничего не устанавливает**.

Textual (`8.2.8`) ставится **только с явного согласия** в отдельное Python-окружение `/opt/kvpn-node-deployer-textual`. На минимальных/offline VPS остаются прежние `whiptail` и текстовое меню, а все CLI-команды работают **без Textual**. `nano` не требуется.

> **Граница ответственности:** установщик **не устанавливает Remnawave Panel**, не создаёт VPN-профили, REALITY-ключи, подписки, маршруты RU→Foreign или балансировку. Всё это настраивается в вашей Remnawave Panel. Рабочая нода появится только после назначения ей корректного Config Profile и настройки Xray в панели.
>
> **Безопасность:** `wizard`, `node` и первоначальный `firewall` предназначены для **нового VPS**, а не действующего VPN-сервера. Мониторинг можно установить отдельно; существующая конфигурация мониторинга не перезаписывается автоматически. Перед операциями с UFW обеспечьте доступ к консоли провайдера.

## Версия приложения

Версия K-VPN Node Deployer хранится в единственном файле [VERSION](VERSION) и показывается в заголовке Textual, резервных меню и через командную строку без root и без установки зависимостей:

```bash
bash install.sh --version
bash kvpn-install.sh --version
```

Это версия **самого приложения**, а не библиотеки Textual. Для релиза обновите `VERSION`, пересоберите `kvpn-install.sh` и опубликуйте Git-тег `vX.Y.Z`.

## Что именно можно сделать

- **Проверить VPS** (`preflight`) — ОС, память, диск, сетевые порты, Docker, UFW. Только чтение.
- **Установить Docker + Compose** (`docker`) — из официального репозитория Docker. Не заменяет уже установленный Docker.
- **Настроить UFW** (`firewall`) — SSH, Node API **только от IP Remnawave Panel**, входящий TCP-порт для клиентов RU или RU-источников на Foreign.
- **Установить только Remnawave Node** (`node`) — использует `docker-compose.yml` **из Remnawave Panel**; требует заранее настроенный UFW.
- **Выполнить полный мастер** (`wizard`) — Docker + Node + UFW, затем **по желанию** резервные копии, HTTPS-цель и агент мониторинга.
- **Добавить новый RU-адрес в UFW Foreign** (`firewall-add-ru`) — только для Foreign-ноды, установленной этим инструментом, без перезапуска Xray.
- **Настроить локальный HTTPS-сайт для REALITY** (`decoy`) — nginx на **`127.0.0.1:9444`**, сертификат Let's Encrypt; DNS и HTTP/80 обязательны. Не настраивает Xray автоматически.
- **Создать ежедневную резервную копию** (`backup`) — локальные архивы `/root/server-backups`, хранение около 14 суток. Архивы содержат **секреты** и не отправляются во внешнее хранилище.
- **Включить независимый TCP-мониторинг** (`monitor ...`) — панель-приёмник с Telegram-уведомлениями, несколько агентов RU→Foreign и локальных Foreign-проверок, отдельный Probe ID и SSH-ключ для каждой.
- **Посмотреть состояние или сохранить диагностику** (`status`, `diagnostics`) — без перенастройки сервисов; диагностика может содержать IP-адреса.

## На каких серверах запускать

- **Host-Panel / мониторинг:** `monitor panel`, затем `monitor register` и `monitor test-telegram`. Мониторинговая панель — **не** Remnawave Panel; эти роли могут размещаться на одном VPS.
- **Node-RU:** `firewall` и `node` **на новом VPS** либо `wizard`; для наблюдения за зарубежным портом — `monitor ru`.
- **Node-Foreign:** `firewall` и `node` **на новом VPS** либо `wizard`; для локальной TCP-проверки — `monitor foreign`.

## Поддерживаемые ОС

Проверяемые установщиком ОС: **Ubuntu 24.04 LTS, 26.04 LTS, 26.10; Debian 12 и 13**. Требуются systemd, APT и права root для установки. Некоторые промежуточные/устаревшие выпуски не допускаются. CI выполняет статические и модульные тесты на Ubuntu 24.04 и 26.04; это **не эквивалентно испытанию всех функций на реальном VPS**.

## Быстрый старт: новый VPS

**1. Подготовка.** Нужны доступ по SSH и к консоли провайдера, публичный IP панели Remnawave, актуальный `docker-compose.yml` для **новой** ноды из панели, отдельный SSH-порт и выбранный входящий TCP-порт Xray. Секретный compose-файл держите с правами `600` и не публикуйте.

**2. Скачайте и изучите установщик.** На **новом VPS**:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl
curl -fL --proto '=https' --tlsv1.2 -o kvpn-install.sh \
  https://raw.githubusercontent.com/RoyMan810/kvpn-node-deployer/main/kvpn-install.sh
bash kvpn-install.sh help
bash kvpn-install.sh preflight
```

Для воспроизводимой установки используйте **конкретный проверенный commit SHA и SHA-256**, а не изменяемую ветку `main`. Не передавайте скачанный скрипт непосредственно в `bash`.

**3. Откройте TUI:**

```bash
sudo bash kvpn-install.sh
```

При первом открытии Textual установщик спросит разрешение добавить `python3-venv` (при необходимости) и установить Textual в изолированное окружение. Если отказаться или установка недоступна, предложит `whiptail`; без него — текстовое меню. Можно сразу открыть старое меню: `KVPN_FORCE_LEGACY_TUI=1 sudo -E bash kvpn-install.sh` либо `sudo bash kvpn-install.sh text-menu` для текстового меню. **Не требуется Python-пакет Textual для обычных CLI-команд.**

**4. Выберите сценарий:**

- **«Полная установка ноды»** — один мастер на чистом VPS; запросит роль `ru`/`foreign`, IP панели, порты, источники трафика, SSH-порт и абсолютный путь к compose-файлу.
- **«Только UFW» → «Только Remnawave Node»** — поэтапная установка. `node` **не меняет** UFW и откажется работать, пока закрытый Node API не подтверждён.
- **«Только Docker»**, **«HTTPS для REALITY»**, **«Резервные копии»**, **«Мониторинг»** — независимые пункты с собственными требованиями.

**5. Завершите настройку в Remnawave Panel:** назначьте Config Profile, настройте реальные Xray inbound/outbound, TLS/REALITY и маршрутизацию; проверьте реальное клиентское подключение. Успешный TCP-тест сам по себе не гарантирует работоспособность VPN.

**Подробные пошаговые руководства:**

- [Textual: установка, горячие клавиши, разделы, безопасность и ошибки](docs/TEXTUAL.md)

- [Новый VPS: роли, порты, UFW, Docker и Remnawave Node](docs/NEW-VPS.md)
- [Мониторинг: Telegram, SSH-ключи, регистрация и несколько проверок](docs/MONITORING.md)
- [HTTPS/REALITY, резервные копии и эксплуатация](docs/SERVICES.md)
- [Диагностика и частые ошибки](docs/TROUBLESHOOTING.md)
- [Для разработчиков: тесты и сборка единого файла](docs/DEVELOPMENT.md)
- [Безопасность](SECURITY.md)

## Справочник команд (без TUI)

```bash
sudo bash kvpn-install.sh tui               # Textual (если доступен) / резервное меню
sudo bash kvpn-install.sh text-menu         # простое меню без зависимости от Python Textual
sudo bash kvpn-install.sh firewall          # только новый VPS
sudo bash kvpn-install.sh docker            # установить Docker + Compose
sudo bash kvpn-install.sh node              # новая нода, после UFW
sudo bash kvpn-install.sh wizard            # всё для новой ноды
sudo bash kvpn-install.sh firewall-add-ru   # разрешить новый RU IP на Foreign
sudo bash kvpn-install.sh decoy             # HTTPS localhost:9444
sudo bash kvpn-install.sh backup            # ежедневный backup
sudo bash kvpn-install.sh monitor panel     # на новой панели мониторинга
sudo bash kvpn-install.sh monitor ru        # на RU: TCP до Foreign
sudo bash kvpn-install.sh monitor foreign   # на Foreign: локальный TCP
sudo bash kvpn-install.sh monitor public-keys # публичные ключи агентов
sudo bash kvpn-install.sh monitor register  # на панели мониторинга
sudo bash kvpn-install.sh monitor status    # статусы / таймеры
sudo bash kvpn-install.sh monitor test-telegram
bash kvpn-install.sh preflight              # чтение, без установки
sudo bash kvpn-install.sh status            # чтение
sudo bash kvpn-install.sh diagnostics       # создаёт файл диагностики (600)
```

`status` и `preflight` не меняют конфигурацию; `diagnostics` **создаёт** файл, `test-telegram` отправляет сообщение. Другие команды могут устанавливать пакеты, создавать systemd units, изменять UFW или запускать контейнеры — перед выполнением ознакомьтесь с соответствующей инструкцией.

## Известные ограничения

- Настройка Remnawave Panel, Xray-профилей, баланса нагрузки и переключения при отказе **не входит** в установщик.
- Мониторинг проверяет **TCP-доступность порта**, а не успешную авторизацию клиента или всю VPN-цепочку.
- Резервные копии **локальные**, без автоматической отправки во внешнее хранилище и без автоматического восстановления.
- Нет команды автоматического обновления/удаления существующей ноды или мониторинга; повторная установка поверх действующих компонентов блокируется.
- После создания агента необходимо **вручную** зарегистрировать его публичный SSH-ключ на панели и включить systemd-таймер.
- Настройки в Remnawave Panel могут требовать дополнительных портов/протоколов; UFW здесь предназначен для описанного TCP-сценария.

[Официальная документация Remnawave](https://docs.rw/install/remnawave-node/) · [Docker Engine](https://docs.docker.com/engine/install/ubuntu/) · [Исходный код](install.sh)

### Надёжность Textual и ключей мониторинга

Для долгих команд вывод Docker/APT читается частями, поэтому отсутствие перевода строки или очень длинная строка в терминале не обрывает работу Textual. Аварийное завершение уже запущенного Textual не вызывает автоматическое повторное открытие запасного меню; проверьте состояние системы перед повтором. При создании агента мониторинга все записи `ssh-keyscan` проходят проверку по одному заранее подтверждённому SHA256-отпечатку панели. Подробности: [Textual](docs/TEXTUAL.md) и [мониторинг](docs/MONITORING.md).
