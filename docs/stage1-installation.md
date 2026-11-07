# Установка Foundation Stage1

Установщик разворачивает **development-сборку** на свежей Ubuntu Server 24.04 amd64. Он устанавливает API и Worker через Compose, host-native Broker и supervisor через systemd. Доступно только наблюдение `host.probe`; production mutation, автоматическое обновление и миграция существующей БД этим установщиком не разрешены.

Нужны rootful Docker Engine 29.x, Compose plugin v2, host Python 3.13 с SQLite ≥3.45, OpenSSL 3 и systemd. Интерпретатор Python должен находиться по постоянному доверенному пути: host supervisor использует его независимо от контейнеров. Минимальная конфигурация Controller — 2 CPU, 4 GiB RAM, 40 GiB диска. Установщик проверяет свободный высокий loopback-порт, существующие namespace, пользователей и units до создания данных. Установка Docker/Python и подписанные самостоятельные host-runtime artifacts относятся к следующей упаковке bootstrap/release.

## Подписанный комплект

На доверенной build-машине Python 3.13 создайте комплект из **зафиксированного коммита**. `--signing-key` указывает на внешнее хранилище 32-байтного Ed25519 seed издателя. Этот ключ отличается от offline Owner age identity и не копируется в комплект или на Controller. Первичный доверенный публичный ключ доставляется на Controller независимо от комплекта.

```bash
python deploy/build_bundle.py --output /path/hostorbit-bundle \
  --signing-key /offline/release-signing.seed \
  --python-image docker.io/library/python@sha256:<verified-digest>
```

Комплект содержит подпись manifest, wheelhouse с закреплёнными зависимостями, их SHA-256 lock, ограниченный CycloneDX SBOM, Dockerfile и host profiles. Bundle builder получает зависимости; установка на Controller выполняет pip с `--no-index --require-hashes` из проверенных локальных wheels. Для OCI base используется digest; pull не обращается к API хостинг-провайдера. Полный SBOM ОС/base image и production release trust-chain пока не приняты.

Доверенный bootstrap запускается из проверенного checkout. Его stdlib verifier проверяет Ed25519 через системный OpenSSL **до исполнения кода из комплекта**. Сначала проверяется подпись по отдельно предоставленному root-owned public key, затем копируются только разрешённые файлы и проверяются их размеры/SHA-256. Родительские symlinks и hardlinks не допускаются. Копия создаётся в закрытом каталоге root; изменяемый исходный комплект дальше не исполняется.

## Свежая установка

Сначала доступны полная проверка входных файлов и preflight. `--development` явно выбирает текущий канал разработки. Этот флаг не открывает mutating adapters и не заменяет приёмку MVP.

```bash
sudo /trusted/python3.13 deploy/installer.py install \
  --bundle /path/hostorbit-bundle --trust-key /etc/hostorbit-release.pub \
  --development --origin https://hostorbit.example --port 18080 --check
```

Для установки выполните ту же команду без `--check`. Public key имеет 32 raw Ed25519 bytes, принадлежит root и закрыт от записи группой. Он должен находиться вне переданного комплекта. Не передавайте приватный signing seed или Owner recovery identity на Controller.

По умолчанию inventory пуст: ни одна VPS не получает скрытого разрешения. `--targets /root/approved-targets.json` позволяет передать предварительно проверенную владельцем политику по текущему контракту `deploy/runtime.example.json` / `docs/stage1-runtime.md`. Это первоначальное provisioning, не публичная регистрация или расширение scope через API. Изменение защищённой policy после запуска требует отдельного maintenance workflow; простая замена файла не обходит authority binding.

Установщик создаёт `/opt/hostorbit`, `/etc/hostorbit`, `/var/lib/hostorbit` и узкие служебные accounts/groups. Если namespace, данные, ключи или users уже существуют, установка останавливается. Прерванная установка оставляет `install-state.json` для диагностики; повтор не стирает и не переинициализирует данные. Восстановление и schema 1→2 должны идти через отдельную управляемую миграцию с Backup Gate.

## Запуск и доступ

`hostorbit-compose.service` управляет двумя контейнерами. API публикуется только на `127.0.0.1:18080`, Worker имеет `network_mode: none`. У обоих read-only rootfs, отдельные numeric UID и host user namespace mapping, пустые capabilities и no-new-privileges. Только Worker получает bind mounts Unix sockets и необходимые supplementary groups. Vault, runtime DEK, private gate journal и Docker socket не монтируются ни в API, ни в Worker.

Broker и supervisor запускаются реальными systemd socket units. Root-owned source DEK доступен Broker через `LoadCredential`, а не через общий bind mount. Доступ AF_UNIX проверяется по `SO_PEERCRED`; параметры JSON не задают identity. Setgid-каталог SQLite с отдельной группой обеспечивает совместную запись API/Worker. Host code принадлежит root и недоступен службам для записи.

Compose не загружает приложение из registry при каждом старте: local image tag связан с подписанным bundle digest, `pull_policy=never`, а systemd перед запуском сверяет фактический image ID с защищённой installation metadata. Подмена local tag блокирует запуск. Это bootstrap development channel, не готовая система self-update/A/B.

Owner создаётся **только локально**:

```bash
sudo /opt/hostorbit/admin create-owner --username roman
```

Пароль вводится скрыто и не передаётся в argv, env или install logs. Внутренний одноразовый bootstrap token потребляется этим локальным действием; первый Web-посетитель не создаёт Owner. `admin verify-image` используется systemd для проверки образа.

Существующие DNS, system Nginx/Caddy, certificates, firewall и listeners 80/443 не изменяются. Для Web API владелец подключает свой HTTPS reverse proxy к loopback endpoint, сохраняет публичный `Host`, устанавливает `X-Forwarded-Proto: https` и заменяет `X-Forwarded-For` фактическим адресом клиента. Root configuration доверяет только loopback и обнаруженному gateway внутренней Compose-сети. HTTP healthz сообщает liveness; он не удостоверяет remote health или DR readiness. Recovery остаётся `NOT_READY` до полного backup/restore workflow.

## Проверки

Локальные unit tests проверяют подпись/подмену manifest и wheel, пути, ограничения канала/схемы, trust-key permissions, отсутствие signing seed в копии и контракт namespaces. Отдельный job запускается только на disposable GitHub-hosted Ubuntu VM: устанавливает пакет и настоящие units, проверяет peer credentials контейнерного Worker, отсутствие privilege mounts API, занятый чужой порт 443, локальное создание Owner и вход через проверенный HTTPS proxy, повторную установку и restart Compose service. Итог CI записывается после фактического прогона; эта документация сама по себе не присваивает PASS оставшимся AC.
