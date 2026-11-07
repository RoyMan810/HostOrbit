# Проверка миграции Foundation БД

Команда `migration-rehearsal` проверяет переход исторической схемы 1 в текущую схему 2 **на отдельных приватных копиях**. Рабочая БД открывается SQLite в `mode=ro` с `query_only=ON`. Одна read transaction закрепляет согласованную WAL-точку для обеих копий через SQLite Online Backup API. Записи обычного приложения могут продолжаться; отчёт относится к закреплённой точке, а не обещает отсутствие последующих записей.

Пример для root-консоли с установленным host runtime:

```bash
sudo /opt/hostorbit/venv/bin/hostorbit \
  --database /var/lib/hostorbit/app/controller.sqlite3 \
  --database-owner "$(id -u ho-api)" --database-group "$(getent group ho-app-db | cut -d: -f3)" \
  migration-rehearsal --output /var/tmp/hostorbit-migration-review-001
```

Каталог вывода должен быть новым; существующий каталог или symlink не заменяется. Родители должны быть доверенными и недоступными для чужой записи; корневой sticky `/var/tmp` допустим. Вывод получает mode `0700`, файлы `0600`. Копии содержат password hashes и server-side sessions, поэтому сохраняются только для локального root review. Это не зашифрованный ControllerBackup и не off-host копия.

Исторический `schema_v1.sql` взят из коммита `f23e066ecab184d1f3f731917b78a382b3f59179` и дополнительно закреплён SHA-256 внутри пакета. Проверяется весь набор таблиц, индексов и триггеров, `integrity_check`, foreign keys и Audit/Outbox chain. Одного `user_version=1` недостаточно; дополнительная таблица, отсутствующее ограничение, повреждённый аудит или неизвестная схема запрещают продолжение. Свежая установка уже создаёт схему 2 и в этой миграции не нуждается.

Миграция копии создаёт таблицы очереди, добавляет событие `database.schema_migrated` с признаком `rehearsal` и меняет `user_version` в **одной транзакции**. SQL выполняется по statement, без `executescript`, который мог бы неявно завершить открытую транзакцию. Сравнивается дайджест всех исходных строк: пользователи, password hashes, роли, grants, сессии, лимиты, bootstrap, reauth и исходный Audit/Outbox должны сохраниться. Новые таблицы остаются пустыми. После commit копия открывается заново и проверяется повторно.

Файлы `source.sqlite3` и `migrated.sqlite3` остаются в каталоге review. `rehearsal.json` содержит только состояния, количество строк и дайджесты, без содержимого credentials. Успех — только `REHEARSAL_PASSED`. Ошибка даёт `FAILED`; `RUNNING` после kill/reboot также не означает успех. Бюджет репетиции — 30 секунд с monotonic clock и SQLite progress/backup callbacks. Ошибка до commit откатывает DDL и version на копии; смерть после commit может оставить согласованную схему 2, но не успешный отчёт. Рабочая база не заменяется, downgrade не выполняется.

## Граница текущего блока

Команды live apply пока нет. Успешная репетиция не выдаёт maintenance permit, не подтверждает Vault/DEK portability, `RESTORE_ATTESTED` или DR readiness. Для применения к рабочей БД требуется связать утверждённый update plan и подписанный совместимый release с независимым host authority, согласованной off-host ControllerBackup ≤30 минут, проверенной restore-процедурой и host TimeHealth. [Host TimeHealth](stage1-time-health.md) уже проверяется независимым supervisor; его привязка к live migration остаётся частью следующего updater workflow. Эти предусловия не заменяются boolean-флагами или `--force`.

Тесты проверяют реальную схему 1, committed WAL, параллельного writer, сохранение Auth/session и целостности аудита, schema drift, broken FK/Audit, отказ Outbox и `SIGKILL` до/после commit. Отдельный installation job выполняет CLI из установленного подписанного wheel на временной Ubuntu VM. [Stage1 Foundation принят](../evidence/acceptance/stage1-2026-11-08/README.md); live migration и полный MVP release gate остаются открытыми.
