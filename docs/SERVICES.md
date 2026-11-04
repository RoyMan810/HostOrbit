# Дополнительные сервисы: HTTPS REALITY, резервное копирование и диагностика

Все функции доступны через TUI `sudo bash kvpn-install.sh` или прямые команды. Эти инструкции описывают **что меняется** и **как проверить** результат.

## 1. Локальный HTTPS-сайт для REALITY

Команда:

```bash
sudo bash kvpn-install.sh decoy
```

Пункт TUI: **«HTTPS-сайт для REALITY»**.

**Для чего:** получить настоящий сертификат Let's Encrypt и поднять nginx, принимающий HTTPS **только на `127.0.0.1:9444`**. Позднее вы указываете этот адрес как `dest`/`target` для REALITY в соответствующем Xray Config Profile **в Remnawave Panel**. Скрипт **не** меняет profile, SNI и REALITY-ключи.

**Что нужно до запуска:**

1. Нода уже установлена этим инструментом (`/etc/kvpn-node-deployer/node.env` существует).
2. Домен с публичной DNS A-записью, указывающей на VPS. Пример **документационного** домена `example.com` не используйте для настоящего выпуска сертификата — нужен **свой** домен.
3. Публичный TCP `80` должен быть свободен, доступен извне и разрешён в облачном firewall/UFW на момент ACME HTTP-01. Для последующих продлений порт 80 **должен оставаться доступным**.
4. Локальный TCP `9444` свободен; чужой nginx default site не должен быть установлен.
5. Email для регистрации сертификата.

После ввода домена и email скрипт проверяет доступность портов и DNS, устанавливает `certbot` и `nginx`, выпускает сертификат, добавляет nginx site и hook `systemctl reload nginx` после успешного обновления сертификата.

**Проверка на этой же ноде** (подставьте свой домен):

```bash
sudo nginx -t
sudo ss -lnt | grep ':9444'
curl -fsS --noproxy '*' --resolve your-domain.example:9444:127.0.0.1 \
  https://your-domain.example:9444/ -o /dev/null
sudo certbot certificates
```

У `ss` должно быть **`127.0.0.1:9444`**, **не** `0.0.0.0:9444`. Публичные `443`/`8443` от этого действия не открываются. Если nginx, HTTP/80 или сертификаты уже управляются другой системой, **не** применяйте этот мастер поверх неё — настраивайте вручную. Certbot `renew` обычно запускается по системному timer дистрибутива; проверьте его самостоятельно.

## 2. Резервные копии новой ноды

```bash
sudo bash kvpn-install.sh backup
```

Пункт TUI: **«Ежедневные резервные копии»**. Команда требует `/opt/remnanode`; на панели без ноды отдельно не устанавливается. Создаёт `kvpn-node-backup.service`/`.timer` и одноразово запускает первый бэкап. Расписание: примерно **03:30 UTC ежедневно**, плюс случайная задержка до 15 минут. Архивы `/root/server-backups/kvpn-node-YYYY-MM-DD_HH-MM-SS.tar.gz` и контрольные суммы `*.sha256`; локальные архивы старше ~14 суток удаляются.

**Что архивируется, если существует:** `/opt/remnanode`, `/etc/kvpn-node-deployer`, конфигурации nginx, Let's Encrypt, UFW, SSH, sysctl, netplan, fstab, logrotate и мониторинга. Архивы содержат **секреты**, включая приватные SSH-ключи и Telegram-токен при их наличии. Права `600`, каталог root-only.

**Проверка:**

```bash
sudo systemctl status kvpn-node-backup.timer --no-pager
sudo systemctl start kvpn-node-backup.service
sudo journalctl -u kvpn-node-backup.service -n 20 --no-pager
sudo ls -lh /root/server-backups
```

При восстановлении сначала проверьте SHA-256 и **содержимое** архива. Автоматическое восстановление не реализовано. Для защиты от потери VPS нужна **отдельная зашифрованная офсайт-копия** и проверенная процедура восстановления. Повторный `backup` при существующем таймере не перезаписывает файлы.

## 3. Проверка и диагностика

**Только чтение:**

```bash
bash kvpn-install.sh preflight
sudo bash kvpn-install.sh status
sudo bash kvpn-install.sh monitor status
```

**Создание диагностического файла:**

```bash
sudo bash kvpn-install.sh diagnostics
```

Диагностика сохраняется как root-only файл `/root/kvpn-node-diagnostics-YYYYMMDD-HHMMSS.txt`. Скрипт не копирует содержимое compose-файла, приватных ключей или токенов, но в отчёте **могут быть IP, версии пакетов, имена контейнеров и внутренние порты**. Всегда просматривайте файл перед передачей третьим лицам.

Пример системных проверок:

```bash
sudo ufw status numbered
sudo systemctl list-timers 'kvpn*' --all --no-pager
cd /opt/remnanode && sudo docker compose ps
```

Если команда `cd /opt/remnanode` завершается ошибкой, нода на этом сервере не установлена.

## 4. Установка только Docker

```bash
sudo bash kvpn-install.sh docker
```

Устанавливает Docker Engine + Compose из официального Docker APT-репозитория, после подтверждения. Если Docker уже есть, но Compose отсутствует, скрипт **не заменяет** существующую установку и прекращает действие — исправьте её вручную. Проверьте:

```bash
sudo docker version
sudo docker compose version
sudo systemctl is-active docker
```

Docker в режиме `host` и другие контейнеры с опубликованными портами могут влиять на правила firewall; правила доступа ко всему VPS нужно оценивать отдельно.

[README](../README.md) · [Новая нода](NEW-VPS.md) · [Частые ошибки](TROUBLESHOOTING.md)
