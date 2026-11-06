#!/usr/bin/env python3
"""K-VPN Textual interface: safe UI layer over the existing Bash installer.

No VPN/system changes are performed by importing or opening this module.
Only the explicit, allowlisted Bash actions below may be executed.
"""
from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass
import os
import signal
from pathlib import Path
import shutil
import sys

from textual import work
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Footer, Header, Input, Label, ListItem, ListView, RichLog, Static

PROTOCOL = "__KVPN_UI_PROMPT__\t"
CANCEL = "__KVPN_UI_CANCEL__"
ROOT = Path(__file__).resolve().parents[1]
APP_VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()


@dataclass(frozen=True)
class Task:
    key: str
    title: str
    category: str
    description: str
    argv: tuple[str, ...]
    modifies: bool = True
    warning: str = ""


TASKS = (
    Task("preflight", "Проверка VPS", "ДИАГНОСТИКА", "ОС, RAM, диски, порты, Docker и UFW. Без изменений.", ("preflight",), False),
    Task("status", "Состояние сервисов", "ДИАГНОСТИКА", "Текущие контейнеры, firewall, таймеры, nginx и SSH-порты.", ("status",), False),
    Task("monitor-status", "Состояние мониторинга", "ДИАГНОСТИКА", "Отчёты и таймеры панели или локальных агентов.", ("monitor", "status"), False),
    Task("monitor-keys", "Публичные SSH-ключи", "ДИАГНОСТИКА", "Вывести только публичные SSH-ключи мониторинговых агентов.", ("monitor", "public-keys"), False),
    Task("docker", "Установить Docker", "НОВАЯ НОДА", "Официальные Docker Engine и Compose из APT-репозитория.", ("docker",)),
    Task("firewall", "Настроить UFW", "НОВАЯ НОДА", "Закрытый Node API, SSH и разрешённые источники VPN.", ("firewall",), True, "Только новый VPS. Неверные SSH/UFW правила могут отключить доступ. Нужна консоль провайдера."),
    Task("node", "Установить Remnawave Node", "НОВАЯ НОДА", "Использует compose из Remnawave Panel; требует уже защищённый UFW.", ("node",), True, "Только новый VPS; нужна compose-конфигурация от панели с правами 600."),
    Task("wizard", "Полная установка ноды", "НОВАЯ НОДА", "Docker, UFW, Remnawave Node и дополнительные компоненты.", ("wizard",), True, "Только чистый VPS. Может менять firewall, Docker и systemd."),
    Task("firewall-add-ru", "Добавить RU-источник", "СЕТЬ", "Добавить один RU IPv4/CIDR для Foreign-ноды, установленной этим инструментом.", ("firewall-add-ru",), True, "Добавляется правило UFW. Подходит только для управляемой Foreign-ноды."),
    Task("decoy", "HTTPS для REALITY", "СЕРВИСЫ", "Nginx + Let's Encrypt на 127.0.0.1:9444; нужен свой домен и TCP/80.", ("decoy",), True, "Нужны корректные DNS, сертификат и свободные порты. Существующий nginx может конфликтовать."),
    Task("backup", "Резервное копирование", "СЕРВИСЫ", "Локальные ежедневные бэкапы ноды с секретами; хранение 14 суток.", ("backup",)),
    Task("monitor-panel", "Установить мониторинг на панели", "МОНИТОРИНГ", "Создаёт отдельный приёмник статусов и Telegram-уведомления.", ("monitor", "panel"), True, "Не перезаписывает существующую панель мониторинга. Нужны chat_id, thread_id и токен бота."),
    Task("monitor-ru", "Добавить RU-проверку", "МОНИТОРИНГ", "Проверять TCP-порт зарубежной ноды с RU-сервера.", ("monitor", "ru")),
    Task("monitor-foreign", "Добавить Foreign-проверку", "МОНИТОРИНГ", "Проверять локальный TCP-порт Xray на Foreign-сервере.", ("monitor", "foreign")),
    Task("monitor-register", "Зарегистрировать агента", "МОНИТОРИНГ", "Привязать отдельный публичный SSH-ключ и source IP к Probe ID.", ("monitor", "register")),
    Task("monitor-telegram", "Тест Telegram", "МОНИТОРИНГ", "Отправить одно тестовое сообщение в настроенную тему.", ("monitor", "test-telegram")),
    Task("diagnostics", "Сохранить диагностику", "СЕРВИСЫ", "Создаёт root-only файл с настройками и состоянием (без содержимого секретов).", ("diagnostics",), True, "В отчёте могут присутствовать IP и имена хостов. Просмотрите перед отправкой."),
)
TASK_MAP = {task.key: task for task in TASKS}


def decode_prompt(line: str) -> tuple[str, str, str] | None:
    """Parse a complete, private prompt frame (not regular command output)."""
    if not line.startswith(PROTOCOL):
        return None
    parts = line.rstrip("\r\n").split("\t")
    if len(parts) != 4 or parts[1] not in ("input", "password", "confirm"):
        return None
    try:
        question, default = (
            base64.b64decode(item, validate=True).decode("utf-8") for item in parts[2:]
        )
    except (ValueError, UnicodeDecodeError):
        return None
    return parts[1], question, default


async def bounded_output_lines(reader, maximum: int = 16384):
    """Yield newline-delimited output without StreamReader's 64 KiB line limit.

    Child programs (especially apt and Docker) may produce extremely long lines
    or carriage-return progress updates. Never buffer an unbounded line or
    abandon an installation merely because its output has no newline.
    """
    pending = bytearray()
    truncated = False
    while chunk := await reader.read(4096):
        parts = chunk.split(b"\n")
        for index, piece in enumerate(parts):
            if not truncated:
                available = maximum - len(pending)
                pending.extend(piece[:available])
                if len(piece) > available:
                    truncated = True
            if index < len(parts) - 1:
                if truncated:
                    yield bytes(pending) + b" [long output line truncated]"
                else:
                    yield bytes(pending)
                pending.clear()
                truncated = False
    if pending or truncated:
        yield bytes(pending) + (b" [long output line truncated]" if truncated else b"")


async def stop_subprocess(proc: asyncio.subprocess.Process) -> None:
    """Stop an unfinished Bash command and its children if the UI aborts."""
    if proc.returncode is not None:
        return
    # The child runs in a new process group; never signal the UI's group.
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        await asyncio.wait_for(proc.wait(), timeout=4)
    except asyncio.TimeoutError:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        await proc.wait()


class AskScreen(ModalScreen[str | None]):
    """One step in the shell wizard, with masked secrets and explicit cancellation."""

    BINDINGS = [("escape", "cancel", "Отмена")]

    def __init__(self, kind: str, question: str, default: str = "") -> None:
        super().__init__()
        self.kind, self.question, self.default = kind, question, default

    def compose(self) -> ComposeResult:
        with Container(id="dialog"):
            yield Static("◆  ПАРАМЕТРЫ K-VPN", classes="dialog-head")
            yield Label(self.question.strip(), id="dialog-question")
            if self.kind != "confirm":
                yield Input(value=self.default, password=self.kind == "password", id="value")
                if self.kind == "password":
                    yield Static("Секрет скрыт и не записывается в журнал.", classes="dialog-note")
                else:
                    yield Static("Enter — продолжить · Esc — отмена", classes="dialog-note")
            else:
                yield Static("Подтвердите только если понимаете последствия действия.", classes="dialog-note")
            with Horizontal(id="dialog-actions"):
                yield Button("Отмена", id="cancel", variant="default")
                yield Button("Да, продолжить" if self.kind == "confirm" else "Продолжить", id="submit", variant="warning" if self.kind == "confirm" else "primary")

    def on_mount(self) -> None:
        if self.kind != "confirm":
            self.query_one("#value", Input).focus()
        else:
            self.query_one("#cancel", Button).focus()

    def on_input_submitted(self, _: Input.Submitted) -> None:
        self.action_submit()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "submit":
            self.action_submit()
        else:
            self.action_cancel()

    def action_submit(self) -> None:
        self.dismiss("yes" if self.kind == "confirm" else self.query_one("#value", Input).value)

    def action_cancel(self) -> None:
        self.dismiss(None)


class ApprovalScreen(ModalScreen[bool]):
    BINDINGS = [("escape", "cancel", "Отмена")]

    def __init__(self, task: Task) -> None:
        super().__init__()
        self.operation = task

    def compose(self) -> ComposeResult:
        with Container(id="dialog"):
            yield Static("◆  ПОДТВЕРЖДЕНИЕ", classes="dialog-head")
            yield Label(self.operation.title, id="dialog-question")
            yield Static(self.operation.warning or "Операция может изменять конфигурацию сервера.", classes="dialog-note")
            yield Static("Изменения не откатываются автоматически. Запуск только на подходящем сервере.", classes="dialog-note")
            with Horizontal(id="dialog-actions"):
                yield Button("Вернуться", id="cancel")
                yield Button("Запустить действие", id="submit", variant="warning")

    def on_mount(self) -> None:
        self.query_one("#cancel", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "submit")

    def action_cancel(self) -> None:
        self.dismiss(False)


class KVpnApp(App):
    TITLE = "K-VPN  •  CONTROL CENTER"
    SUB_TITLE = f"v{APP_VERSION}  /  Textual  /  SSH console"
    BINDINGS = [("q", "safe_exit", "Выход"), ("r", "refresh", "Обновить"), ("f5", "refresh", "Обновить")]
    CSS = """
    Screen { background: #0c1020; color: #e6edff; }
    Header { background: #131d33; color: #f7fbff; }
    Footer { background: #131d33; }
    #shell { height: 1fr; }
    #sidebar { width: 34; background: #10192d; border-right: solid #28465d; padding: 1 1; }
    #brand { text-style: bold; color: #60f5dc; height: 3; padding: 1 1 0 1; }
    #sidebar-note { color: #94abc2; height: 3; padding: 0 1; }
    #nav { height: 1fr; background: transparent; }
    ListItem { height: 2; padding: 0 1; color: #b8cbe0; }
    #main { width: 1fr; padding: 1 2; }
    #hero { height: 3; color: #60f5dc; text-style: bold; }
    #title { height: 2; text-style: bold; color: #ffffff; }
    #description { height: 3; color: #afc4d9; }
    #actions { height: 4; align: left middle; }
    #actions Button { margin-right: 2; }
    #status-title, #log-title { height: 1; margin-top: 1; text-style: bold; color: #6df4de; }
    #inventory { height: 8; background: #141f35; border: round #314e68; }
    #log { height: 1fr; background: #10182a; border: round #314e68; padding: 0 1; }
    Button { border: none; }
    #run { background: #0e7f7d; color: white; }
    #refresh { background: #334a67; }
    #exit { background: #48344d; }
    #working { color: #ffd17b; height: 1; }
    AskScreen, ApprovalScreen { align: center middle; background: #000000 65%; }
    #dialog { width: 70; max-width: 95%; height: auto; padding: 2 3; border: round #5ad6ce; background: #16243b; }
    .dialog-head { height: 2; color: #6ef4e0; text-style: bold; }
    #dialog-question { height: auto; min-height: 2; color: #ffffff; margin-bottom: 1; }
    #value { margin-bottom: 1; }
    .dialog-note { color: #9cb8d0; height: auto; margin: 1 0; }
    #dialog-actions { height: 4; align: right middle; }
    #dialog-actions Button { margin-left: 1; }
    """

    def __init__(self, root: Path = ROOT) -> None:
        super().__init__()
        self.root = root
        self.selected = TASKS[0]
        self.busy = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="shell"):
            with Vertical(id="sidebar"):
                yield Static(f"◆  K-VPN  /  SYSTEM  v{APP_VERSION}", id="brand")
                yield Static("Выберите действие · Enter\nЗапуск — отдельной кнопкой", id="sidebar-note")
                yield ListView(*(ListItem(Label(f"{i + 1:02d}  {t.title}"), id=f"task-{t.key}") for i, t in enumerate(TASKS)), id="nav")
            with Vertical(id="main"):
                yield Static("✦  ПРОВЕРЯЙ · НАСТРАИВАЙ · НАБЛЮДАЙ", id="hero")
                yield Static(self.selected.title, id="title")
                yield Static(self.selected.description, id="description")
                with Horizontal(id="actions"):
                    yield Button("▶  Выполнить", id="run", variant="primary")
                    yield Button("↻  Обновить статус", id="refresh")
                    yield Button("Выход", id="exit")
                yield Static("СОСТОЯНИЕ ЭТОГО СЕРВЕРА", id="status-title")
                yield DataTable(id="inventory", zebra_stripes=True, show_cursor=False)
                yield Static("ЖУРНАЛ ВЫПОЛНЕНИЯ", id="log-title")
                yield RichLog(id="log", wrap=True, markup=False, max_lines=1600)
                yield Static("Готово к работе. VPN и мониторинг не меняются при открытии меню.", id="working")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#inventory", DataTable).add_columns("Компонент", "Состояние")
        self.query_one("#nav", ListView).focus()
        self.query_one("#log", RichLog).write("K-VPN Control Center · Textual\nВыберите раздел слева. Операции установки запрашивают подтверждение.")
        self.refresh_inventory()

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        if event.item is not None:
            self._select(event.item.id)

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        self._select(event.item.id)

    def _select(self, widget_id: str | None) -> None:
        if widget_id and widget_id.startswith("task-"):
            self.selected = TASK_MAP[widget_id.removeprefix("task-")]
            self.query_one("#title", Static).update(self.selected.title)
            mode = "ЧТЕНИЕ" if not self.selected.modifies else "ИЗМЕНЕНИЕ СИСТЕМЫ"
            self.query_one("#description", Static).update(f"{self.selected.description}\nРежим: {mode}")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "run":
            self.execute_selected()
        elif event.button.id == "refresh":
            self.action_refresh()
        elif event.button.id == "exit":
            self.action_safe_exit()

    def action_safe_exit(self) -> None:
        if self.busy:
            self.notify("Идёт операция. Дождитесь завершения: прерывание может оставить частичную установку.", severity="warning")
        else:
            self.exit()

    def action_refresh(self) -> None:
        if not self.busy:
            self.refresh_inventory()

    def _set_busy(self, value: bool) -> None:
        self.busy = value
        self.query_one("#run", Button).disabled = value
        self.query_one("#refresh", Button).disabled = value
        self.query_one("#exit", Button).disabled = value
        self.query_one("#nav", ListView).disabled = value
        self.query_one("#working", Static).update("● Выполняется... Подтверждайте шаги во всплывающих окнах." if value else "● Готово. Можно выбрать следующее действие.")

    @work(exclusive=True, group="inventory")
    async def refresh_inventory(self) -> None:
        table = self.query_one("#inventory", DataTable)
        rows = [
            ("Remnawave Node", "настроена" if Path("/opt/remnanode/docker-compose.yml").is_file() else "не обнаружена"),
            ("Мониторинг / Panel", "настроен" if Path("/etc/kvpn-monitor/config.json").is_file() else "нет"),
            ("Мониторинг / Агентов", str(len(tuple(Path("/etc/kvpn-monitor/probes").glob("*.env"))))),
        ]
        for name, unit in (("Docker", "docker.service"), ("Таймер мониторинга", "kvpn-monitor-kit.timer"), ("Таймер бэкапа", "kvpn-node-backup.timer")):
            state = "недоступно"
            if shutil.which("systemctl"):
                proc = None
                try:
                    proc = await asyncio.create_subprocess_exec("systemctl", "is-active", unit, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
                    output, _ = await asyncio.wait_for(proc.communicate(), timeout=3)
                    state = output.decode(errors="replace").strip() or "неизвестно"
                except asyncio.TimeoutError:
                    # A hung systemctl must not survive successive dashboard refreshes.
                    if proc is not None and proc.returncode is None:
                        proc.kill()
                        await proc.wait()
                    state = "тайм-аут"
                except OSError:
                    state = "ошибка проверки"
            rows.append((name, state))
        table.clear()
        for row in rows:
            table.add_row(*row)

    @work(exclusive=True, group="execution")
    async def execute_selected(self) -> None:
        if self.busy:
            return
        task = self.selected
        if task.modifies and not await self.push_screen_wait(ApprovalScreen(task)):
            return
        self._set_busy(True)
        log = self.query_one("#log", RichLog)
        log.write(f"\n▶ {task.title}  ·  bash install.sh {' '.join(task.argv)}")
        env = os.environ.copy()
        env.pop("KVPN_TUI", None)
        env["KVPN_TEXTUAL_IPC"] = "1"
        env["DEBIAN_FRONTEND"] = "noninteractive"
        proc: asyncio.subprocess.Process | None = None
        try:
            proc = await asyncio.create_subprocess_exec(
                "bash", str(self.root / "install.sh"), *task.argv,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                cwd=str(self.root), env=env,
                start_new_session=True,
            )
            assert proc.stdout and proc.stdin
            async for raw in bounded_output_lines(proc.stdout):
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                prompt = decode_prompt(line)
                if prompt is not None:
                    response = await self.push_screen_wait(AskScreen(*prompt))
                    if response is None:
                        response = CANCEL
                    try:
                        proc.stdin.write((response + "\n").encode("utf-8"))
                        await proc.stdin.drain()
                    except (BrokenPipeError, ConnectionResetError):
                        log.write("Поток ввода закрыт преждевременно.")
                else:
                    # Strip ANSI/control codes from potentially untrusted output.
                    line = "".join(c for c in line if c == "\t" or ord(c) >= 32)
                    if line:
                        log.write(line)
            exit_code = await proc.wait()
            log.write(f"● Завершено: код {exit_code}" if exit_code else "✓ Операция завершилась успешно.")
            self.notify("Готово" if exit_code == 0 else "Ошибка выполнения — см. журнал", severity="information" if exit_code == 0 else "error")
        except asyncio.CancelledError:
            log.write("⚠ Интерфейс завершился во время операции; проверяйте состояние служб перед повтором.")
            raise
        except Exception as exc:
            log.write(f"Ошибка выполнения команды: {exc}")
            self.notify("Ошибка выполнения — см. журнал", severity="error")
        finally:
            if proc is not None:
                if proc.stdin is not None:
                    proc.stdin.close()
                await stop_subprocess(proc)
            self._set_busy(False)
            self.refresh_inventory()


if __name__ == "__main__":
    KVpnApp().run()
