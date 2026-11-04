# Если что-то не работает: диагностика K-VPN Node Deployer

**Не запускайте полный мастер повторно поверх работающей ноды.** Он предназначен для нового VPS и откажется перезаписывать существующую конфигурацию. Для безопасной диагностики сначала используйте `preflight`, `status` и журналы, не меняйте UFW наугад.

## TUI не открылось

- Требуется интерактивный SSH-терминал с корректным `$TERM` и размером минимум **65 столбцов × 20 строк**.
- Если `whiptail` отсутствует, установщик предлагает установить его через APT. Без него доступно текстовое меню.
- Если терминал не поддерживает TUI, используйте прямые команды: `bash kvpn-install.sh help`.
- При запуске из cron/CI используйте только команды чтения. Мастера установки требуют ручных подтверждений.

## «Unsupported or EOL OS»

Проверьте `cat /etc/os-release`. Поддерживаются ровно версии, перечисленные в [README](../README.md). Настройка и пакеты Docker для других версий **не проверялись**; не подменяйте VERSION_ID вручную.

## Ошибка UFW / пропал SSH

- Если UFW не активен и вы настраиваете новый VPS, убедитесь, что указан **реальный SSH-порт** и `sshd` его слушает.
- Если UFW **уже активен**, скрипт не расширяет существующие SSH-правила; проверьте доступ вручную.
- Если доступ потерян, подключайтесь через **консоль провайдера**, а не меняйте вслепую удалённые настройки.

```bash
sudo ufw status verbose
sudo ufw status numbered
sudo ss -lnt | grep -E ':(22|2222|443|8443) '
```

Установка только `node` требует уже **активный UFW с deny incoming**, запрет глобального Node API и разрешение от точного IP панели.

## Docker или Node не запустились

На новом VPS:

```bash
sudo docker compose version
cd /opt/remnanode && sudo docker compose ps
cd /opt/remnanode && sudo docker compose logs --tail=80
sudo systemctl status docker --no-pager
```

Если `docker compose config` сообщает о несоответствии `NODE_PORT/APP_PORT`, нужен **фактический порт из Remnawave Panel**, а не угаданное значение. Не присылайте полный compose или `docker inspect`: они могут содержать секреты.

Если image pull не прошёл, **файлы новой ноды и UFW не меняются**, но Docker/зависимости могли установиться. Если ошибка произошла **после** создания `/opt/remnanode`, повторно запускать `wizard` нельзя: настройку нужно диагностировать вручную.

Если контейнер работает, но VPN не поднимается — проверьте Config Profile, Xray inbound/outbound, REALITY-ключи, порт и реальную цепочку в Remnawave Panel; установщик не управляет этими параметрами.

## Не удалось получить SSH Ed25519 ключ мониторинговой панели

На **агенте**:

```bash
ssh-keyscan -T 10 -p 22 -t ed25519 PANEL_IP
```

Подставьте **реальный адрес панели мониторинга** вместо `PANEL_IP`; порт может отличаться от `22`. Установщик повторяет попытку до 3 раз, **но никогда не отключает проверку SHA256**. Проверьте доступность TCP SSH-порта панели со стороны агента и ограничения входящего UFW/провайдера. На **самой панели** через доверенную консоль получите реальный отпечаток:

```bash
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Если SSH-host fingerprint не совпал — **остановитесь**, не принимайте неизвестный ключ. Не включайте `StrictHostKeyChecking=no` и не удаляйте `known_hosts` для обхода ошибки.

## «Invalid Ed25519 public key» при `monitor register`

В поле `Paste node PUBLIC ssh-ed25519 key` надо вставить **всю строку**, начинающуюся с `ssh-ed25519 AAAA…`, а не IP и не SHA256 fingerprint. На **агенте** получите её:

```bash
sudo bash kvpn-install.sh monitor public-keys
```

В следующем поле `Source IP` введите **исходящий публичный IP агента**. При NAT узнайте адрес egress. Не вводите здесь адрес цели Xray.

## Мониторинг говорит OK, но VPN не работает

`OK` — только TCP connect. Проверьте реальные подключения с клиентского устройства. Отдельно проверяйте: доступ RU→Foreign, локальный Xray, Config Profile, сертификаты/ключи, маршруты и выход в Интернет.

## На панели нет отчётов / STATUS_ACCEPTED отсутствует

На **агенте** проверьте его экземпляр таймера (ID замените своим):

```bash
sudo systemctl is-active 'kvpn-monitor-kit-probe@ru1-nl1.timer'
sudo systemctl start 'kvpn-monitor-kit-probe@ru1-nl1.service'
sudo journalctl -u 'kvpn-monitor-kit-probe@ru1-nl1.service' -n 30 --no-pager
```

На **панели мониторинга**:

```bash
sudo bash kvpn-install.sh monitor status
sudo journalctl -u kvpn-monitor-kit.service -n 30 --no-pager
```

Проверьте ключ, Probe ID, зарегистрированный Source IP, права `kvpn-probe` на SSH и доступ к порту SSH панели. При первом запуске `INIT` до получения первого отчёта — нормальное состояние.

## Telegram не приходит

```bash
sudo bash kvpn-install.sh monitor test-telegram
sudo journalctl -u kvpn-monitor-kit.service -n 30 --no-pager
```

Проверьте бота в группе, права отправки, `chat_id`, `message_thread_id` и исходящий доступ к `api.telegram.org:443`. При неполадке Telegram уведомления остаются в `/var/lib/kvpn-monitor/outbox`; при восстановлении связи возможны задержка и **повтор сообщения** в редком случае неопределённого результата доставки. **Не публикуйте** содержимое `/etc/kvpn-monitor/token`.

## HTTPS для REALITY не выпустил сертификат

Проверьте A-запись домена и внешний TCP/80, отсутствие другого веб-сервера на 80, `sudo certbot certificates`, `sudo nginx -t`. Для локального сайта проверить `127.0.0.1:9444`, а не внешний 9444. Разрешение порта в UFW недостаточно, если его блокирует firewall провайдера.

[README](../README.md) · [Мониторинг](MONITORING.md) · [Эксплуатация](SERVICES.md)
