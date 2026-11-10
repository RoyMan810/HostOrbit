# Повторная автоматическая проверка Stage1 Foundation

Шесть reports относятся к исходному commit `3a2be3cb9dd6767740e9111c64ae22fdd8a53fd5`. Исторические отчёты в `evidence/capabilities/stage1/` и предыдущие решения сохранены без изменений. Gate использует эту директорию, если она существует; при её отсутствии использует историческую. Отсутствие отдельного текущего report или изменение связанного файла блокирует Stage1.

`source-manifest.json` и каждый report связывают SHA-256 проверенных исходников, deploy-конфигурации, тестов и зависимостей. Подписанный development bundle на этой ревизии отдельно собран на disposable Ubuntu 24.04 VPS с Python 3.15.2. Подпись и содержимое проверены через `deploy.artifact.snapshot`; сохранены его manifest, подпись, SBOM и только **открытый одноразовый тестовый ключ**. Закрытый seed удалён. Это тестовый подписант, не production release authority. SBOM не охватывает всю ОС или base image.

`ci-observations.json` содержит публичные job/step metadata [GitHub Actions](https://github.com/RoyMan810/HostOrbit/actions/runs/42799650204) на том же commit. Указанные в reports Foundation suites и native jobs завершились успешно, но workflow целиком завершился **failure** из-за quality и прежних несоответствующих evidence. Подробные исходные логи GitHub без авторизации получить не удалось; независимая ручная проверка их содержимого не заявляется. Новый CI после изменения gate и tools tests должен пройти отдельно.

Reports подтверждают только автоматическую повторную проверку ограниченных capabilities Foundation. Они не подтверждают Stage2/MVP, полную нагрузочную приёмку, независимый DR, Owner restore attestation или готовность production. Утверждения более широких исторических reports не переносятся автоматически на этот commit.
