# Установка контроллера

[Документация](README.md)

## Установка одной командой

На чистой Ubuntu Server 24.04 или 26.04 (amd64) с работающим systemd:

```sh
git clone https://github.com/RoyMan810/VPN-Orbit.git
sudo ./VPN-Orbit/install
```

Для bootstrap требуется интернет. Для сборки рекомендуется 2 ГиБ RAM и 6 ГиБ свободного места в `/var/lib`. При меньшем объёме установщик выводит предупреждение и продолжает работу. Число параллельных задач при сборке Python зависит от объёма памяти и числа CPU. Установка собирает Python 3.15.2 из официального архива по закреплённому SHA-256. Если Docker отсутствует, установка добавляет подписанный репозиторий Docker и ставит Engine 29.x, Compose и Buildx. Существующий Docker должен поддерживать тот же профиль. Конфликтующие пакеты и установки VPN-Orbit остаются на месте, а операция останавливается.

Controller и WebUI собираются из коммита текущего checkout. Изменения в отслеживаемых файлах приводят к отказу. Сборка Controller использует закреплённые хеши Python-зависимостей и OCI digest. Одноразовый локальный подписант development-комплекта удаляется после сборки. Источник доверия здесь — выбранный вами checkout и закреплённые в нём зависимости. Ручной сценарий ниже принимает комплект с независимо доставленным ключом издателя. Node.js нужен только для сборки статики из npm lock. При установке регистрируются host-native Broker и Supervisor через systemd, API и Worker через Compose и отдельный HTTPS reverse proxy Nginx. Установщик извлекает Nginx из пакетов Ubuntu. По умолчанию выделенная служба слушает loopback.

В интерактивном терминале установка предлагает задать пароль Owner. По умолчанию используется имя `admin`. Для другого имени укажите `--owner roman`. Для запуска без терминала или повтора ввода после ошибки используйте `sudo /opt/vpn-orbit/admin create-owner --username admin`.

С рабочего компьютера скопируйте публичный сертификат CA и установите доверие к нему в используемом браузере. Затем откройте SSH-туннель:

```sh
scp ubuntu@CONTROLLER:/opt/vpn-orbit-bootstrap/web-ca.pem .
ssh -N -L 127.0.0.1:18443:127.0.0.1:18443 ubuntu@CONTROLLER
```

Откройте [https://127.0.0.1:18443](https://127.0.0.1:18443) и войдите как Owner. Замените `ubuntu@CONTROLLER` на вашу учётную запись и адрес. Локальный сертификат действует 397 дней. Nginx слушает только `127.0.0.1:18443`, а API — `127.0.0.1:18080`. Docker при запуске устанавливает стандартные сетевые правила для своих контейнеров. При ошибке сборки можно повторить команду. Если Controller уже начал установку, проверьте `/opt/vpn-orbit/install-state.json` и журналы systemd. Повторная установка потребует отдельного обслуживания.

### Публичный HTTPS

Если контроллеру нужен публичный адрес, направьте A-запись домена на VPS и заранее выпустите сертификат Certbot с именем домена. Пример для VPS со свободными TCP 80 и 443:

```sh
sudo apt install certbot
sudo certbot certonly --standalone --cert-name orbit.example.org -d orbit.example.org \
  --deploy-hook 'systemctl try-restart vpn-orbit-web.service'
sudo ./VPN-Orbit/install --public-domain orbit.example.org
```

Режим `--public-domain` проверяет сертификат и ключ до установки. Nginx слушает IPv4 TCP 443, а API остаётся на `127.0.0.1:18080`. Начальный Owner создаётся локально на VPS. Для продления через standalone TCP 80 должен быть доступен Certbot. Deploy hook перезапускает выделенный Nginx, чтобы systemd перечитал сертификат и ключ. Системный Nginx и занятые порты требуют отдельного согласования конфигурации.

Для завершённого локального Rescue import доступен отдельный [recovery installation](stage1-recovery-installation.md) через `--recovery-state`; он сохраняет READ_ONLY_RECOVERY и не открывает повторный Owner bootstrap.

Постоянные родительские каталоги установки (`/opt`, `/etc`, `/var/lib`, `/run` и их ancestors) должны принадлежать root и не допускать group/other write. Preflight отказывает с `INSTALLATION_PARENT_UNTRUSTED` до создания состояния и не меняет права чужих системных каталогов. Disposable CI fixture отдельно проверяет отказ на `/opt` 0777, затем готовит защищённый профиль 0755 только в своей временной VM.

Установщик разворачивает **development-сборку** на Ubuntu Server 24.04 или 26.04 amd64. API и Worker работают через Compose, Broker и Supervisor — через systemd. Для проверки наблюдений настройте [SSH-цель](#подготовка-vps-по-паролю-или-ssh-ключу). Для тестового перезапуска нужен [отдельный профиль стенда](stage2-inventory.md#сквозная-проверка-перезапуска-на-стенде).

Нужны rootful Docker Engine 29.x, Compose plugin v2 или v5 (включая версии пакетов Ubuntu с суффиксом `+ds…ubuntu…`), Docker Buildx для offline-сборки образа, host Python 3.15 для нового комплекта (Python 3.13 для старого), SQLite ≥3.45, OpenSSL 3 и systemd. Интерпретатор Python должен находиться по постоянному доверенному пути: host supervisor использует его независимо от контейнеров. Для ручной установки рекомендуются 1 vCPU, 2 ГиБ RAM и 2 ГиБ свободного места в `/var/lib`. Проверка ресурсов выводит предупреждение при значениях ниже этих рекомендаций. Offline Rescue имеет отдельные [требования к памяти и изоляции](stage1-rescue.md). Установщик проверяет свободный высокий loopback-порт, существующие namespace, пользователей и units до создания данных. В ручном сценарии ниже Docker и Python готовятся заранее.

## Подписанный комплект

На доверенной build-машине Python 3.15 создайте комплект из **зафиксированного коммита**. `--signing-key` указывает на внешнее хранилище 32-байтного Ed25519 seed издателя. Этот ключ отличается от offline Owner age identity и не копируется в комплект или на Controller. Первичный доверенный публичный ключ доставляется на Controller независимо от комплекта.

```bash
python deploy/build_bundle.py --output /path/vpn-orbit-bundle \
  --signing-key /offline/release-signing.seed \
  --python-image docker.io/library/python@sha256:<verified-digest> \
  --age-tool /verified/age-v1.3.2-linux-amd64/age
```

Комплект содержит подпись manifest, wheelhouse с закреплёнными зависимостями, их SHA-256 lock, ограниченный CycloneDX SBOM, Dockerfile и host profiles. Builder экспортирует исходники только из указанного текущим `HEAD` коммита: неотслеживаемые и игнорируемые файлы не попадают в wheel. До сборки он проверяет зависимости по [закреплённым хешам](../deploy/requirements-wheels.lock), а build backend устанавливает в отдельное окружение по [отдельному lock](../deploy/requirements-build.lock). При обновлении версий нужны проверка происхождения и обновление обоих соответствующих pins; хеши сами по себе не доказывают безопасность издателя или build-машины. Установка на Controller выполняет pip с `--no-index --require-hashes` из проверенных локальных wheels. Для OCI base используется digest; pull не обращается к API хостинг-провайдера. Полный SBOM ОС/base image и production release trust-chain пока не приняты.

Builder также требует официальный binary `age` v1.3.2 linux/amd64 с закреплённым SHA-256 `eb7dd1b518f0a307c99cd97782623c5321da049154b04acd2d98d21aa7bc9b2c`. Он входит в подписанный manifest/SBOM и устанавливается как root-owned `/opt/vpn-orbit/tools/age` (0755). Подмена версии запрещается stdlib verifier даже при корректной подписи bundle; байты проверяются до исполнения. Offline Owner identity и `age-keygen` на Controller не устанавливаются. Предыдущий development bundle без инструмента читается verifier, но новая установка отказывает с `PINNED_AGE_TOOL_REQUIRED`.

Доверенный bootstrap запускается из проверенного checkout. Его stdlib verifier проверяет Ed25519 через системный OpenSSL **до исполнения кода из комплекта**. Сначала проверяется подпись по отдельно предоставленному root-owned public key, затем копируются только разрешённые файлы и проверяются их размеры/SHA-256. Родительские symlinks и hardlinks не допускаются. Копия создаётся в закрытом каталоге root; изменяемый исходный комплект дальше не исполняется.

## Свежая установка

Сначала доступны полная проверка входных файлов и preflight. `--development` явно выбирает текущий канал разработки. Доступные операции определяет защищённая политика целей.

```bash
sudo /trusted/python3.15 deploy/installer.py install \
  --bundle /path/vpn-orbit-bundle --trust-key /etc/vpn-orbit-release.pub \
  --development --origin https://vpn-orbit.example --port 18080 --check
```

Для установки выполните ту же команду без `--check`. Public key имеет 32 raw Ed25519 bytes, принадлежит root и закрыт от записи группой. Он должен находиться вне переданного комплекта. Не передавайте приватный signing seed или Owner recovery identity на Controller.

По умолчанию inventory пуст: ни одна VPS не получает скрытого разрешения. `--targets /root/approved-targets.json` позволяет передать предварительно проверенную владельцем политику по текущему контракту `deploy/runtime.example.json` / `docs/stage1-runtime.md`. Это первоначальное provisioning, не публичная регистрация или расширение scope через API. Изменение защищённой policy после запуска требует отдельного maintenance workflow; простая замена файла не обходит authority binding.

Свежая подписанная сборка создаёт SQLite со схемой 4, общей очередью задач и таблицей черновиков Change Plan. Установщик создаёт `/opt/vpn-orbit`, `/etc/vpn-orbit`, `/var/lib/vpn-orbit` и узкие служебные accounts/groups. Если namespace, данные, ключи или users уже существуют, установка останавливается. Прерванная установка оставляет `install-state.json` для диагностики; повтор не стирает и не переинициализирует данные. Восстановление и schema 1→2 должны идти через отдельную управляемую миграцию с Backup Gate.

## Запуск и доступ

`vpn-orbit-compose.service` управляет двумя контейнерами. API публикуется только на `127.0.0.1:18080`, Worker имеет `network_mode: none`. У обоих read-only rootfs, отдельные numeric UID и host user namespace mapping, пустые capabilities и no-new-privileges. Только Worker получает bind mounts Unix sockets и необходимые supplementary groups. Vault, runtime DEK, private gate journal и Docker socket не монтируются ни в API, ни в Worker.

Broker и supervisor запускаются реальными systemd socket units. Runtime DEK запечатывается `systemd-creds --with-key=host` в root-owned `.cred`; Broker получает расшифрованную приватную копию через `LoadCredentialEncrypted`. Открытый DEK не записывается во временный файл и не передаётся в argv/env. Чужой host key или credential name не подходят для дешифрования. Доступ AF_UNIX проверяется по `SO_PEERCRED`; параметры JSON не задают identity. Setgid-каталог SQLite с отдельной группой обеспечивает совместную запись API/Worker. Host code принадлежит root и недоступен службам для записи.

Compose не загружает приложение из registry при каждом старте: local image tag связан с подписанным bundle digest, `pull_policy=never`, а systemd перед запуском сверяет фактический image ID с защищённой installation metadata. Подмена local tag блокирует запуск. Это bootstrap development channel, не готовая система self-update/A/B.

Owner создаётся **только локально**:

```bash
sudo /opt/vpn-orbit/admin create-owner --username roman
```

Пароль вводится скрыто и не передаётся в argv, env или install logs. Внутренний одноразовый bootstrap token потребляется этим локальным действием; первый Web-посетитель не создаёт Owner. `admin verify-image` используется systemd для проверки образа.

Существующие DNS, системный Nginx, certificates, firewall и listeners 80/443 не изменяются. Для Web API владелец подключает свой HTTPS reverse proxy к loopback endpoint, сохраняет публичный `Host`, устанавливает `X-Forwarded-Proto: https` и заменяет `X-Forwarded-For` фактическим адресом клиента. Root configuration доверяет только loopback и обнаруженному gateway отдельной Compose-сети. HTTP healthz сообщает liveness; он не удостоверяет remote health или DR readiness. Recovery остаётся `NOT_READY` до полного backup/restore workflow.

## Проверки

Локальные unit tests проверяют подпись/подмену manifest и wheel, пути, ограничения канала/схемы, trust-key permissions, отсутствие signing seed в копии и контракт namespaces. Отдельный job запускается только на disposable GitHub-hosted Ubuntu VM: устанавливает пакет и настоящие units, проверяет peer credentials контейнерного Worker, отсутствие privilege mounts API, занятый чужой порт 443, локальное создание Owner и вход через проверенный HTTPS proxy, повторную установку и restart Compose service.

API подключён к отдельному bridge с исходящей связностью: Docker не публикует host ports у контейнера, подключённого только к `internal` network. Порт API указан явно с host IP `127.0.0.1`, тот же адрес задан default binding сети; фактическая публикация проверяется после установки. Worker не подключён к этому bridge. Это не egress firewall для Backend.

### Подготовка VPS по паролю или SSH-ключу

Для свежей управляемой VPS с Ubuntu 24.04 запустите команду с компьютера администратора из доверенного checkout VPN-Orbit. Нужны Python 3 и клиент OpenSSH. Возьмите отпечаток `SHA256:…` из консоли VPS командой `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`.

```sh
python3 tools/prepare_vps.py --host 192.0.2.20 --user ubuntu \
  --fingerprint 'SHA256:…' --output ./managed-vps
```

Замените IP, имя пользователя и отпечаток своими значениями. OpenSSH запросит пароль входа, а `sudo` при необходимости запросит пароль повышения прав. Для входа своим SSH-ключом добавьте `--identity ~/.ssh/id_ed25519`. Для нестандартного порта добавьте `--port`. Команда создаёт отдельный аккаунт наблюдения и сразу проверяет вход с новым ключом VPN-Orbit.

Для команды `prepare_vps.py` используйте Controller или машину, чей SSH-адрес разрешён для наблюдения на управляемой VPS. Подготовьте цель до свежей установки. Передайте `managed-vps/targets.json` как `sudo ./VPN-Orbit/install --targets ./managed-vps/targets.json`. Режим регистрации в WebUI включится автоматически. Сохраните Resource ID, Secret Reference и напечатанный при создании ID Owner. Импортируйте приватный ключ наблюдения на Controller:

```sh
sudo install -d -m 0700 -o vpn-orbit-broker -g vpn-orbit-broker /run/vpn-orbit/key-import
sudo install -m 0600 -o vpn-orbit-broker -g vpn-orbit-broker \
  ./managed-vps/probe /run/vpn-orbit/key-import/probe
sudo systemd-run --wait --pipe --collect \
  --property=User=vpn-orbit-broker --property=Group=vpn-orbit-broker \
  --property=UMask=0077 \
  --property=LoadCredentialEncrypted=broker-dek:/etc/vpn-orbit/credentials/broker-dek.cred \
  /opt/vpn-orbit/venv/bin/vpn-orbit-runtime --config /etc/vpn-orbit/runtime.json import-key \
  --key-file /run/vpn-orbit/key-import/probe --target "$TARGET_ID" \
  --secret-id "$SECRET_ID" --owner-id "$OWNER_ID"
sudo rm /run/vpn-orbit/key-import/probe
```

Подставьте `TARGET_ID` из Resource ID, `SECRET_ID` из Secret Reference без суффикса `:v1` и `OWNER_ID` из команды создания владельца. Удаляйте временную копию после успешного импорта. В WebUI подтвердите fingerprint по шагам ниже. Привилегии перезапуска требуют отдельной политики.

### Подключение подготовленной VPS владельцем

Для новой установки укажите `install --targets /root/approved-targets.json --web-enrollment` вместе с обычными параметрами установки. Root заранее утверждает IP, CIDR, SSH host key и ссылку на ключ для каждой VPS. Подготовьте ограниченную учётную запись и импортируйте ключ наблюдения по [инструкции runtime](stage1-runtime.md). Установщик передаёт API проекцию утверждённой политики наблюдения с IP, портом и отпечатком SSH. Inventory до подтверждения пуст.

1. В доверенной консоли VPS выполните `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256`. Скопируйте значение `SHA256:…`.
2. Откройте WebUI, установленный bootstrap. При ручной установке скачайте готовый WebUI из GitHub Actions той же ревизии и опубликуйте `dist/` в корне HTTPS-домена Controller с проксированием `/api/` по [инструкции WebUI](../web/README.md#сборка-и-запуск). Войдите как Owner. В Inventory откройте «Подключить VPS» и укажите утверждённый IP и порт, пользователя SSH, пароль или приватный ключ без парольной фразы и отпечаток из консоли. Controller проверяет ключ сервера во время SSH-рукопожатия и регистрирует VPS после успешной аутентификации. SSH-пароль и приватный ключ используются только для этой проверки. Для ранее подготовленных целей доступно подключение по ID из политики.
3. `POST /api/v1/enrollment/ssh` принимает JSON с `ip`, `port` (по умолчанию 22), `username`, `fingerprint` и одним из полей `password` или `private_key`. Запрос требует session cookie, текущие `Origin` и `X-CSRF-Token`. Ответ 201 содержит `Location` карточки. Ответ 412 означает несовпадение отпечатка, 424 — отказ в SSH-аутентификации, 404 — отсутствие утверждённой цели, 409 — повторную или неоднозначную регистрацию. Путь через ID использует `POST /api/v1/resources` с `resource_id` и `fingerprint`.
4. После подключения через панель SSH-проверка запускается автоматически. Карточка показывает результат. При подключении напрямую через API запустите SSH-наблюдение отдельно. Для оператора выдайте `vps:read` и `vps:probe` на конкретный ID. Worker и Broker проверяют исходную root-политику и привязку SSH-ключа при выполнении.
