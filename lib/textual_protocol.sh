#!/usr/bin/env bash
# Private, line-based UI bridge for the Textual launcher. The installation
# helpers remain fully usable without this environment flag.
# Prompts go to stderr (not command-substitution stdout), replies to stdin.
kvpn_ipc_request() {
  [[ "${KVPN_TEXTUAL_IPC:-0}" == 1 ]] || return 2
  local kind="$1" question="$2" default="${3:-}" reply
  local q64 d64
  q64=$(printf %s "$question" | base64 -w0) || return 1
  d64=$(printf %s "$default" | base64 -w0) || return 1
  printf '__KVPN_UI_PROMPT__\t%s\t%s\t%s\n' "$kind" "$q64" "$d64" >&2
  IFS= read -r reply || return 1
  [[ "$reply" != '__KVPN_UI_CANCEL__' ]] || return 1
  # Do not print, log or export the reply except the expected stdout value.
  printf '%s' "$reply"
}
kvpn_ipc_confirm() {
  local result
  result=$(kvpn_ipc_request confirm "$1" '') || return 1
  [[ "$result" == yes ]]
}
