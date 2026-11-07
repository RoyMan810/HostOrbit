# Проверка runtime Stage1

Первый полный сквозной прогон с усиленными границами прошёл на ревизии `22796a3ab0de13a07df047639ce0a1e467a85a08`, tree `33ba3c652f52df0c80c701c60698109495e94b65`. [CI 42348148670](https://github.com/RoyMan810/HostOrbit/actions/runs/42348148670) включает 36 тестов приложения, 18 contract tests runtime, прежние 60 Stage0 tests, четыре SFTP tests и отдельные SSH/Docker/Broker стенды.

[Стенд разных UID](https://github.com/RoyMan810/HostOrbit/actions/runs/42348148670/job/128330291775) подтвердил совместную запись API и Worker в application SQLite при отдельной группе, успешный SSH probe через Broker и authority, а также EACCES на private stores и sockets из API. Пользователь с socket group, но другим UID, получил отказ SO_PEERCRED. Worker не смог запросить maintenance permit. Повтор nonce и подмена подписанного target отклонены.

Remote stdout с canary дал FAILED без canary в application SQLite и SSE. Замена реального server host key дала SSH_HOST_KEY_MISMATCH. При работе первого Worker второй процесс не смог получить flock. После SIGKILL первого Worker его Job сохранил UNKNOWN_OUTCOME, хотя Broker позднее сохранил успешную квитанцию. Задание повторно не исполнялось.

Systemd parser проверил service/socket profiles. В копиях для syntax verification путь установленного entry point заменён существующим Python executable; это проверка синтаксиса, не полноценная установка этих units. Контракт socket activation проверен реальным inherited AF_UNIX listener на fd 3. Стенд использует один kernel и отдельный network namespace для managed SSH.

[Сборка пакета](https://github.com/RoyMan810/HostOrbit/actions/runs/42348148670/job/128330291598) создала wheel `hostorbit-0.1.0.dev1-py3-none-any.whl`, SHA-256 `fba50c09912a0f778c2473f87c67ae87c1c25f5a30061883f230bd46ea8381f5`. Этот digest относится к указанной ревизии. Проверка состава исключила лабораторные пакеты из wheel и подтвердила `remote_mutation_enabled=false` в development manifest. Последующие regression checks отдельно добавляют проверку подмены полного metadata/blob pair между Secret References и отказ от частичного Vault init без ключа.

Stage0 review bundle дополнительно проверен по целостности. У всех 15 черновых отчётов совпали evidence digest, source/build binding, hashes manifest/SBOM и список обязательных критериев registry. Это техническое ревью целостности артефактов. Outcome остаётся NOT_RUN, acceptance reviewer отсутствует; оно не присваивает критериям PASS. Canonical registry и его статусы не изменялись этим срезом.

Runtime имеет один включённый read-only adapter. Полные mutating Change Plans, backup/time/reconciliation gates, Compose installation, безопасная миграция schema 1 и formal Stage1 acceptance остаются отдельной работой. Проверенные наблюдения не удостоверяют готовность MVP к эксплуатации.
