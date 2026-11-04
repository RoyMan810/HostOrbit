#!/usr/bin/env bash
# Isolated Textual dependency. Nothing is installed unless the operator opts in.
KVPN_TEXTUAL_VENV=/opt/kvpn-node-deployer-textual
KVPN_TEXTUAL_VERSION=8.2.8

kvpn_textual_python() {
  local interpreter
  for interpreter in "$KVPN_TEXTUAL_VENV/bin/python" "$(command -v python3 || true)"; do
    [[ -n "$interpreter" && -x "$interpreter" ]] || continue
    if "$interpreter" - <<'PY' >/dev/null 2>&1
from importlib.metadata import version
from textual.app import App
assert version('textual').split('.')[0] == '8'
PY
    then
      printf '%s' "$interpreter"
      return 0
    fi
  done
  return 1
}

kvpn_textual_offer_install() {
  [[ "$(id -u)" -eq 0 && -r /dev/tty && -t 0 && -t 1 && "${TERM:-dumb}" != dumb ]] || return 1
  printf '\nK-VPN: красивый терминальный интерфейс требует Python Textual %s.\n' "$KVPN_TEXTUAL_VERSION" > /dev/tty
  printf 'Установить python3-venv (при необходимости) и Textual в %s? [yes/no] ' "$KVPN_TEXTUAL_VENV" > /dev/tty
  local response
  read -r response < /dev/tty || return 1
  [[ "$response" == yes ]] || return 1
  if ! command -v python3 >/dev/null 2>&1 || ! python3 -c "import venv,ensurepip" >/dev/null 2>&1; then
    apt-get update -qq || return 1
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 python3-venv ca-certificates || return 1
  fi
  if [[ -e "$KVPN_TEXTUAL_VENV" ]]; then
    echo "Existing virtual environment is unusable: $KVPN_TEXTUAL_VENV. Inspect it manually." >&2
    return 1
  fi
  install -d -m 755 /opt
  python3 -m venv "$KVPN_TEXTUAL_VENV" || return 1
  if ! "$KVPN_TEXTUAL_VENV/bin/python" -m pip install --disable-pip-version-check --no-input "textual==$KVPN_TEXTUAL_VERSION"; then
    echo 'Textual installation failed. Run the CLI or legacy menu; do not modify VPN settings.' >&2
    return 1
  fi
  kvpn_textual_python >/dev/null
}

kvpn_textual_launch() {
  [[ -t 0 && -t 1 && "${TERM:-dumb}" != dumb ]] || return 1
  local interpreter
  interpreter=$(kvpn_textual_python) || {
    kvpn_textual_offer_install || return 1
    interpreter=$(kvpn_textual_python) || return 1
  }
  "$interpreter" "$ROOT_DIR/lib/textual_ui.py"
}
