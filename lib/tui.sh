#!/usr/bin/env bash
# K-VPN terminal UI helpers. No Python, nano or third-party Python packages.
# whiptail is optional until a user explicitly launches the visual menu.

# Use the actual SSH terminal dimensions (80x24 works). Smaller terminals
# fall back to the text menu instead of rendering cut-off/corrupt dialogs.
kvpn_ui_geometry() {
  local rows cols
  read -r rows cols < <(stty size < /dev/tty) || return 1
  [[ "$rows" =~ ^[0-9]+$ && "$cols" =~ ^[0-9]+$ ]] || return 1
  (( rows >= 20 && cols >= 65 )) || return 1
  KVPN_UI_W=$(( cols > 94 ? 92 : cols - 2 ))
  KVPN_UI_H=$(( rows > 25 ? 23 : rows - 2 ))
  export KVPN_UI_W KVPN_UI_H
}

kvpn_ui_ready() {
  [[ "${KVPN_TUI:-0}" == 1 ]] && command -v whiptail >/dev/null 2>&1 && [[ -r /dev/tty ]]
}

kvpn_ui_box() {
  local title="$1" message="$2"
  if kvpn_ui_ready; then
    whiptail --backtitle 'K-VPN Node Deployer' --title "$title" \
      --msgbox "$message" 15 "${KVPN_UI_W:-76}"
  else
    printf '\n%s\n%s\n' "$title" "$message" >&2
  fi
}

kvpn_ui_input() {
  local question="$1" default="${2:-}" result
  if kvpn_ui_ready; then
    result=$(whiptail --backtitle 'K-VPN Node Deployer' --title 'Параметры' \
      --inputbox "$question" 13 "${KVPN_UI_W:-76}" "$default" 3>&1 1>&2 2>&3) || return 1
    printf '%s' "$result"
  else
    [[ -r /dev/tty ]] || return 1
    if [[ -n "$default" ]]; then
      read -r -p "$question [$default]: " result < /dev/tty || return 1
    else
      read -r -p "$question: " result < /dev/tty || return 1
    fi
    printf '%s' "${result:-$default}"
  fi
}

kvpn_ui_password() {
  local question="$1" result
  if [[ "${KVPN_TEXTUAL_IPC:-0}" == 1 ]]; then
    kvpn_ipc_request password "$question" ''
    return $?
  fi
  if kvpn_ui_ready; then
    result=$(whiptail --backtitle 'K-VPN Node Deployer' --title 'Секретное значение' \
      --passwordbox "$question\n\nТокен не сохраняется в истории терминала." \
      14 "${KVPN_UI_W:-76}" 3>&1 1>&2 2>&3) || return 1
    printf '%s' "$result"
  else
    [[ -r /dev/tty ]] || return 1
    read -rsp "$question " result < /dev/tty || return 1
    printf '\n' > /dev/tty
    printf '%s' "$result"
  fi
}

kvpn_ui_confirm() {
  local question="$1" answer
  if kvpn_ui_ready; then
    whiptail --backtitle 'K-VPN Node Deployer' --title 'Подтверждение' \
      --yesno "$question\n\nДа — продолжить; Нет — вернуться без выполнения." 15 "${KVPN_UI_W:-76}"
  else
    [[ -r /dev/tty ]] || return 1
    read -r -p "$question [yes/no] " answer < /dev/tty || return 1
    [[ "$answer" == yes ]]
  fi
}

kvpn_ui_choice_role() {
  if kvpn_ui_ready; then
    whiptail --backtitle 'K-VPN Node Deployer' --title 'Роль сервера' \
      --radiolist 'Выберите роль этой ноды. Используйте стрелки и пробел.' 16 "${KVPN_UI_W:-76}" 4 \
      ru 'Входная нода в России' OFF \
      foreign 'Зарубежная выходная нода' ON 3>&1 1>&2 2>&3
  else
    kvpn_ui_input 'Роль сервера (ru/foreign)' foreign
  fi
}

kvpn_ui_yes_no() {
  local question="$1" default="${2:-no}"
  if kvpn_ui_ready; then
    if whiptail --backtitle 'K-VPN Node Deployer' --title 'Дополнительная настройка' \
      --yesno "$question" 13 "${KVPN_UI_W:-76}"; then
      printf yes
    else
      printf no
    fi
  else
    kvpn_ui_input "$question (yes/no)" "$default"
  fi
}

kvpn_ui_prompt_ru() {
  local original="$1"
  case "$original" in
    'Role (ru / foreign)'|'Server role (ru / foreign)') printf 'Выберите расположение сервера';;
    *'Unique probe ID'*) printf 'Уникальный ID проверки (например, ru1-to-nl1 или nl1-local)';;
    *'Monitoring panel IP/hostname'*) printf 'IP или DNS-имя сервера мониторинга (панели)';;
    *'Panel SSH port'*) printf 'SSH-порт панели мониторинга';;
    *'Foreign node IP/hostname to probe'*) printf 'IP или DNS-имя зарубежной ноды для проверки';;
    *'TCP port to probe'*) printf 'TCP-порт для проверки';;
    *'Panel ED25519 SHA256 fingerprint'*) printf 'Проверенный SHA256-отпечаток SSH-ключа панели (не ключ агента)';;
    *'Paste verified monitoring panel ED25519 SHA256 fingerprint'*) printf 'Проверенный SHA256-отпечаток SSH-ключа панели';;
    *'Probe ID (must match node)'*) printf 'ID проверки, созданной на ноде';;
    *'Readable name'*) printf 'Понятное имя проверки (например, Node-RU → Node-NL TCP 8443)';;
    *'Paste node PUBLIC ssh-ed25519 key'*) printf 'ПУБЛИЧНЫЙ SSH-ключ агента — строка начинается с ssh-ed25519; сюда НЕ вводите IP';;
    *'Source IP of this node'*) printf 'Публичный IP агента, с которого он подключается к панели (не SSH-ключ)';;
    *'Stale threshold seconds'*) printf 'Через сколько секунд без отчётов сообщить UNKNOWN';;
    *'Consecutive failures'*) printf 'Сколько ошибок подряд до тревоги';;
    *'Successes to recover'*) printf 'Сколько успехов до уведомления о восстановлении';;
    *'Telegram group chat_id'*) printf 'Telegram ID группы (например, -100...)';;
    *'Telegram topic message_thread_id'*) printf 'Telegram ID темы внутри группы';;
    *'Remnawave Panel public IPv4'*) printf 'Публичный IPv4 панели Remnawave';;
    *'Node API port'*) printf 'Порт Node API из docker-compose.yml панели';;
    *'Xray TCP inbound port'*) printf 'Входящий TCP-порт Xray';;
    *'Public TCP inbound port'*) printf 'Публичный TCP-порт, на который приходят клиенты';;
    *'RU IP addresses/CIDRs allowed'*) printf 'Разрешённые IP российских серверов через запятую (например 192.0.2.10,192.0.2.11)';;
    *'Allowed RU IPs/CIDRs'*) printf 'IP российских серверов через запятую';;
    *'Current SSH port'*) printf 'Текущий SSH-порт. Проверьте, иначе можно потерять доступ!';;
    *'Current inbound SSH port'*) printf 'Текущий SSH-порт. Проверьте, иначе можно потерять доступ!';;
    *'Absolute path to Panel-generated docker-compose.yml'*) printf 'Полный путь к docker-compose.yml, полученному в Remnawave Panel';;
    *'Allow public 80/tcp for ACME'*) printf 'Открыть порт 80 для сертификата Let's Encrypt?';;
    *'Will you install an ACME'*) printf 'Понадобится HTTPS-сайт для REALITY через Let's Encrypt?';;
    *'New RU source IPv4/CIDR'*) printf 'IP нового российского сервера для разрешения в UFW';;
    *'Hostname for REALITY target'*) printf 'Домен для HTTPS-сайта REALITY';;
    *'Email for Let'*) printf 'Email для выпуска сертификата';;
    *) printf '%s' "$original";;
  esac
}

kvpn_ui_select() {
  local title="$1" prompt="$2"; shift 2
  whiptail --backtitle 'K-VPN Node Deployer' --title "$title" \
    --menu "$prompt" "${KVPN_UI_H:-22}" "${KVPN_UI_W:-76}" "$(( ${KVPN_UI_H:-22} - 8 ))" "$@" 3>&1 1>&2 2>&3
}

kvpn_ui_bootstrap() {
  [[ -r /dev/tty && -t 0 && "${TERM:-dumb}" != dumb ]] || return 1
  kvpn_ui_geometry || return 1
  if command -v whiptail >/dev/null 2>&1; then return 0; fi
  if command -v apt-get >/dev/null 2>&1 && [[ $(id -u) == 0 ]]; then
    printf '\nДля графического меню в терминале нужен пакет whiptail.\n' > /dev/tty
    printf 'Установить whiptail через APT? [yes/no] ' > /dev/tty
    local ans
    read -r ans < /dev/tty || return 1
    if [[ "$ans" == yes ]]; then
      apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends whiptail
      command -v whiptail >/dev/null 2>&1 && return 0
    fi
  fi
  return 1
}

# Read-only commands are shown inside a scrollable dialog (with root-only temp file).
kvpn_ui_readonly() {
  local label="$1"; shift
  local output result=0
  output=$(mktemp) || return 1
  chmod 600 "$output"
  if bash "$KVPN_ROOT/install.sh" "$@" >"$output" 2>&1; then
    :
  else
    result=$?
    printf '\nКоманда завершилась с кодом %s\n' "$result" >>"$output"
  fi
  if kvpn_ui_ready; then
    whiptail --backtitle 'K-VPN Node Deployer' --title "$label" \
      --scrolltext --textbox "$output" "${KVPN_UI_H:-22}" "${KVPN_UI_W:-76}" || :
  else
    cat "$output"
  fi
  rm -f -- "$output"
  return 0
}

kvpn_ui_run_action() {
  local label="$1"; shift
  kvpn_ui_box "$label" "Сейчас откроется мастер параметров.\n\nВы всегда можете отменить действие.\nИзменения выполняются только после подтверждения на нужном шаге."
  if ( export KVPN_TUI=1; bash "$KVPN_ROOT/install.sh" "$@" ); then
    if [[ "${1:-}" == monitor && ( "${2:-}" == ru || "${2:-}" == foreign ) ]]; then
      kvpn_ui_box 'Агент создан' "Осталось зарегистрировать проверку на панели.\n\nПубличный ключ можно повторно посмотреть командой:\ncat /etc/kvpn-monitor/probes/ID.key.pub\n\nЗамените ID на свой Probe ID. После регистрации включите таймер проверки."
    elif [[ "${1:-}" == monitor && "${2:-}" == register ]]; then
      kvpn_ui_box 'Агент зарегистрирован' 'Теперь на сервере агента включите его systemd-таймер и запустите проверку. SSH-ключ и доступ по IP зарегистрированы на панели.'
    else
      kvpn_ui_box 'Готово' "$label\n\nОперация выполнена без ошибок."
    fi
  else
    kvpn_ui_box 'Не завершено' "$label\n\nОперация завершилась с ошибкой или отменена. Проверьте сообщение в терминале выше.\nРаботающий VPN самостоятельно не перезапускается."
  fi
}

kvpn_ui_monitor_menu() {
  local item
  while true; do
    item=$(kvpn_ui_select 'Мониторинг · K-VPN' 'Выберите роль или действие. Каждая проверка имеет отдельный ID.' \
      panel 'Установить приёмник и Telegram-бота на панели' \
      ru 'Создать RU-проверку зарубежной ноды' \
      foreign 'Создать локальную проверку Foreign-ноды' \
      register 'Зарегистрировать SSH-ключ проверки на панели' \
      status 'Показать таймеры и проверки' \
      pubkeys 'Показать публичные SSH-ключи агентов' \
      telegram 'Отправить тестовое Telegram-сообщение' \
      back 'Назад') || return 0
    case "$item" in
      panel) kvpn_ui_run_action 'Мониторинг на панели' monitor panel;;
      ru) kvpn_ui_run_action 'RU-проверка' monitor ru;;
      foreign) kvpn_ui_run_action 'Foreign-проверка' monitor foreign;;
      register) kvpn_ui_run_action 'Регистрация SSH-ключа' monitor register;;
      status) kvpn_ui_readonly 'Состояние мониторинга' monitor status;;
      pubkeys) kvpn_ui_readonly 'Публичные ключи агентов' monitor public-keys;;
      telegram) kvpn_ui_run_action 'Проверка Telegram' monitor test-telegram;;
      back) return 0;;
    esac
  done
}

kvpn_ui_firewall_menu() {
  local item
  while true; do
    item=$(kvpn_ui_select 'Сетевой экран · UFW' 'UFW изменяет правила доступа. При ошибке можно потерять SSH.' \
      setup 'Настроить UFW только на НОВОМ VPS' \
      addru 'Разрешить ещё один RU IP на Foreign-ноде' \
      view 'Просмотреть состояние UFW' \
      back 'Назад') || return 0
    case "$item" in
      setup) kvpn_ui_run_action 'Настройка UFW' firewall;;
      addru) kvpn_ui_run_action 'Разрешить RU IP' firewall-add-ru;;
      view) kvpn_ui_readonly 'Состояние сервисов' status;;
      back) return 0;;
    esac
  done
}

kvpn_ui_main() {
  local item
  export KVPN_ROOT="${KVPN_ROOT:?must provide repository root}"
  while true; do
    item=$(kvpn_ui_select 'K-VPN Node Deployer · Управление' \
      '↑ ↓ — выбор · Enter — открыть · Esc — назад. Установка компонентов независима.' \
      node 'Установить ТОЛЬКО Remnawave Node (новый VPS)' \
      full 'Полная установка ноды по шагам (новый VPS)' \
      ufw 'UFW — firewall и IP российских нод' \
      docker 'Установить Docker + Compose' \
      https 'HTTPS-сайт для REALITY' \
      backup 'Ежедневные резервные копии' \
      monitor 'Мониторинг, регистрация нод, Telegram' \
      preflight 'Проверить сервер (без изменений)' \
      status 'Состояние сервисов' \
      diagnostics 'Сохранить диагностику' \
      quit 'Завершить работу') || break
    case "$item" in
      node) kvpn_ui_run_action 'Remnawave Node · только нода' node;;
      full) kvpn_ui_run_action 'Полная установка новой ноды' wizard;;
      ufw) kvpn_ui_firewall_menu;;
      docker) kvpn_ui_run_action 'Docker + Compose' docker;;
      https) kvpn_ui_run_action 'HTTPS REALITY' decoy;;
      backup) kvpn_ui_run_action 'Резервное копирование' backup;;
      monitor) kvpn_ui_monitor_menu;;
      preflight) kvpn_ui_readonly 'Проверка VPS' preflight;;
      status) kvpn_ui_readonly 'Состояние сервисов' status;;
      diagnostics) kvpn_ui_run_action 'Сохранить диагностику' diagnostics;;
      quit) break;;
    esac
  done
  clear 2>/dev/null || true
}
