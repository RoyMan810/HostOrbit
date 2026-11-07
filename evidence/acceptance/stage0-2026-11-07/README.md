# Приёмка прототипов Stage0

15 обязательных критериев §40 имеют `PASS` после проверки кода и журналов CI. Рецензент — **Codex, автоматическая самопроверка**; независимый человеческий аудит не проводился. Приняты узкие лабораторные прототипы §41. Это не приёмка полного MVP или production mutating capabilities.

Проверенная ревизия: `71d964e18d7251430e0d998022f9ceb6d3bee156`, дерево `a0b11cfb697bd1c7f6f5c729d8e90da33bf53139`. [Основной CI](https://github.com/RoyMan810/HostOrbit/actions/runs/42350989156) и [восстановление после потери VM](https://github.com/RoyMan810/HostOrbit/actions/runs/42350989155) завершились успешно: 66 тестов Stage0, 36 приложения, 20 runtime, четыре SFTP-теста и отдельные native/container/VM стенды.

`review-index.json` перечисляет все отчёты и их дайджесты. Индивидуальные отчёты находятся по `evidence_path` из JSON: `evidence/tests/ac-*.json`. В каждом сохранены точное assertion и его SHA-256, проверенные части утверждения, пути исходников, ссылки на CI jobs и SHA-256 их полных декодированных журналов. Дайджест отчёта покрывает все поля, включая время и тип рецензента.

`source-manifest.json` фиксирует 91 файл проверенной ревизии. `build_digest` — SHA-256 отсортированного списка файлов, сериализованного UTF-8 JSON с отступом 2, `sort_keys=true` и завершающим переводом строки. `sbom.cdx.json` содержит ограниченный состав лаборатории: это не полный SBOM ОС, образов или production-релиза. `ci-observations.json` содержит проверенные наблюдения семи успешных jobs.

`baseline-check.json` сверяет все 71 ID нормативного индекса, stage/release/owner/AC, графы и список Stage0; все 84 AC имеют двустороннюю трассу к описанным feature/control requirements. Связь с capability представлена `linked_requirements`, не флагом включения production action. Stage0 acceptance links к требованиям более позднего этапа не являются зависимостями исполнения.

`HostOrbit_Requirements_Registry_v2.3.json` — точный снимок сопровождающего канонического JSON после обновления статусов. Первоначальный реестр остаётся единственным authority; копия в этом каталоге фиксирует версию приёмки. Остальные 69 AC имеют `NOT_RUN`. Состояния требований и их evidence_status не повышены. `baseline-execution-update.json` связывает прежние и новые контрольные суммы JSON, MD и DOCX; в MD/DOCX добавлен журнал исполнения, нормативные требования и assertions сохранены.

```bash
python -m stage0.requirements evidence/acceptance/stage0-2026-11-07/HostOrbit_Requirements_Registry_v2.3.json --gate Stage0 --evidence-root .
```

Ожидаемый результат: `Stage0 passed`. Для `--gate Stage3` ожидается код `2`: оставшиеся MVP AC ещё блокируют выпуск.

Ограничения прямо записаны в каждом отчёте: общий гипервизор двух гостевых VM и SFTP, автоматическое воспроизведение внешнего оператора/Owner, независимые inventory scopes вместо отдельных production VPS, SIGKILL на границах фаз вместо физического отключения питания и доверенные Backend/root/Docker границы. Подделанный approval в разрешённом scope показан как остаточный риск. Перепроверка полного runtime restore/update, установщика, миграции и этапов 1–3 остаётся обязательной.
