# Переустановка только мониторинга K-VPN

**Инструкция для действующих Node-RU, Node-NL и Host-Panel-NL.** Не запускайте `wizard`, `node`, `firewall` или `docker` на рабочих серверах: здесь меняется **только мониторинг**, а не VPN. При переходе возможен короткий перерыв Telegram-уведомлений.

Новый комплект умеет принимать **несколько RU- и Foreign-нод**. Для каждой проверки задаётся уникальный ID и отдельный SSH-ключ. Проверка из RU (TCP) и локальная проверка Foreign — разные вещи; обе **не гарантируют работу VPN целиком**.

## 1. Проверка и резервные копии

На каждом сервере скачайте установщик и запустите проверку **без изменений**:

```bash
curl -fL --proto '=https' --tlsv1.2 -o kvpn-install.sh \
  https://raw.githubusercontent.com/RoyMan810/kvpn-node-deployer/main/kvpn-install.sh
sudo bash kvpn-install.sh monitor legacy-audit
```

На **Host-Panel-NL** сохраните старый мониторинг, файл авторизации SSH и systemd units (здесь и далее команды запускаются из root shell):

```bash
sudo -i
umask 077
mkdir -p /root/kvpn-monitor-migration-backups
[ ! -d /root/kvpn-monitor ] || tar -czf /root/kvpn-monitor-migration-backups/legacy-panel.tar.gz -C /root kvpn-monitor
[ ! -f /home/kvpn-probe/.ssh/authorized_keys ] || cp -a /home/kvpn-probe/.ssh/authorized_keys /root/kvpn-monitor-migration-backups/legacy-authorized_keys
for u in kvpn-monitor.service kvpn-monitor.timer; do
  [ ! -f "/etc/systemd/system/$u" ] || cp -a "/etc/systemd/system/$u" /root/kvpn-monitor-migration-backups/
done
```

На **Node-RU**:

```bash
sudo -i
umask 077
mkdir -p /root/kvpn-monitor-migration-backups
for u in kvpn-probe.service kvpn-probe.timer; do
  [ ! -f "/etc/systemd/system/$u" ] || cp -a "/etc/systemd/system/$u" /root/kvpn-monitor-migration-backups/
done
[ ! -f /root/.ssh/kvpn_monitor_push ] || cp -a /root/.ssh/kvpn_monitor_push /root/kvpn-monitor-migration-backups/
[ ! -f /usr/local/sbin/kvpn-probe-send.sh ] || cp -a /usr/local/sbin/kvpn-probe-send.sh /root/kvpn-monitor-migration-backups/
```

**Не публикуйте** архивы, Telegram-токен или закрытые SSH-ключи. Перед удалением убедитесь, что резервные копии целые.

## 2. Удалить только старые службы вручную

**Node-RU:**

```bash
systemctl disable --now kvpn-probe.timer
systemctl stop kvpn-probe.service 2>/dev/null || true
rm -f /etc/systemd/system/kvpn-probe.timer /etc/systemd/system/kvpn-probe.service
rm -f /usr/local/sbin/kvpn-probe-send.sh
systemctl daemon-reload
```

Старый ключ `/root/.ssh/kvpn_monitor_push` лучше перенести в закрытую резервную папку после проверки его копии.

**Host-Panel-NL:**

```bash
systemctl disable --now kvpn-monitor.timer
systemctl stop kvpn-monitor.service 2>/dev/null || true
rm -f /etc/systemd/system/kvpn-monitor.timer /etc/systemd/system/kvpn-monitor.service
rm -f /usr/local/libexec/kvpn-probe-receive
systemctl daemon-reload
```

После бэкапа **переместите** старую папку `/root/kvpn-monitor` в закрытое резервное место без перезаписи файлов. В `/home/kvpn-probe/.ssh/authorized_keys` удалите **только старую строку** с `/usr/local/libexec/kvpn-probe-receive`, не удаляя файл или другие ключи:

```bash
grep -nF '/usr/local/libexec/kvpn-probe-receive' /home/kvpn-probe/.ssh/authorized_keys
# Только если это старый ключ K-VPN Monitor:
sed -i '\|/usr/local/libexec/kvpn-probe-receive|d' /home/kvpn-probe/.ssh/authorized_keys
```

Не удаляйте пользователя `kvpn-probe`, не меняйте `sshd_config`, Xray, Remnawave, nginx и UFW. На Node-NL старого агента может не быть: сначала смотрите `legacy-audit`.

## 3. Установить новую схему

**На Host-Panel-NL**, после удаления старой схемы:

```bash
sudo bash kvpn-install.sh monitor panel
sudo bash kvpn-install.sh monitor test-telegram
```

Укажите ID группы Telegram, ID темы и токен бота (скрытый ввод). Панель покажет отпечаток своего SSH Ed25519 host key.

**На каждой российской ноде**, по одной проверке на каждый Foreign-сервер:

```bash
sudo bash kvpn-install.sh monitor ru
```

Пример ID: `ru1-to-nl1`, `ru1-to-nl2`, `ru2-to-nl1`. Введите адрес и TCP-порт Foreign-ноды, адрес панели мониторинга и **независимо проверенный отпечаток SSH host key панели**.

**На каждой зарубежной ноде** для дополнительной локальной проверки (не обязательно):

```bash
sudo bash kvpn-install.sh monitor foreign
```

Пример ID: `nl1-local`.

**После создания каждого агента вернитесь на Host-Panel-NL** и зарегистрируйте его:

```bash
sudo bash kvpn-install.sh monitor register
```

Укажите тот же ID, **публичный** ключ, IP-адрес, с которого агент действительно выходит на панель (в том числе через NAT), и пороги. Для каждого агента — отдельная регистрация.

На соответствующей ноде включите таймер (пример для ID `ru1-to-nl1`):

```bash
sudo systemctl enable --now kvpn-monitor-kit-probe@ru1-to-nl1.timer
sudo systemctl start kvpn-monitor-kit-probe@ru1-to-nl1.service
```

Проверка примерно каждые **5 минут**, оценка на панели раз в **минуту**. По умолчанию два последовательных сбоя вызывают тревогу; отсутствие отчётов более 12 минут означает UNKNOWN; один успех после сбоя — восстановление.

## 4. Контроль

На панели:

```bash
sudo bash kvpn-install.sh monitor status
sudo bash kvpn-install.sh monitor test-telegram
sudo journalctl -u kvpn-monitor-kit.service -n 20 --no-pager
```

На ноде:

```bash
sudo systemctl list-timers 'kvpn-monitor-kit-probe@*' --all --no-pager
sudo journalctl -u kvpn-monitor-kit-probe@ru1-to-nl1.service -n 20 --no-pager
```

Проверьте свежесть отчётов и тестовое сообщение **в нужной теме Telegram**. **Не отключайте рабочий Xray ради теста.** При проблемах сохраните бэкап и восстанавливайте исключительно старые файлы мониторинга и его systemd units. Новый комплект не удаляет старые компоненты автоматически и не должен запускаться поверх них.
