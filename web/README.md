# WebUI HostOrbit

React-интерфейс Stage2 показывает зарегистрированные VPS в области доступа пользователя, результаты SSH-проверок и обнаруженное ПО. Для входа используйте учётную запись Controller. Список и карточка используют существующие серверные права доступа.

Статус SSH относится к текущему наблюдению. История успешной проверки отображается с собственной датой. Состояния Docker и Nginx описывают наличие файлов по проверенным путям на момент наблюдения.

## Сборка и запуск

Соберите frontend на Node.js 24 из зафиксированного исходного кода.

```sh
cd web
npm ci
npm run build
```

Опубликуйте содержимое `dist/` в корне того же HTTPS-домена, который указан как `--origin` при [установке Controller](../docs/stage1-installation.md). Сохраните существующее проксирование `/api/` к loopback endpoint Controller. Статический каталог содержит только файлы сборки и доступен веб-серверу на чтение.

Для существующего Nginx HTTPS server добавьте маршрут статических файлов рядом с маршрутом API.

```nginx
location / {
    root /srv/hostorbit-web/current;
    index index.html;
    try_files $uri $uri/ =404;
    add_header Content-Security-Policy "frame-ancestors 'none'" always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy no-referrer always;
}
```

В браузере откройте корень HTTPS-домена. Сессия использует HttpOnly cookie Controller, а CSRF-токен хранится в памяти страницы. Язык и тема сохраняются в настройках браузера.

## Браузерные проверки

Установите зависимости из `requirements-dev.txt` в Python 3.13, доступный как `python`. Для тестов нужны OpenSSL и Chrome или Chromium. Тесты поднимают локальный HTTPS Controller с одноразовой SQLite и тестовыми учётными записями.

```sh
npm run build
HOSTORBIT_CHROMIUM="$(command -v google-chrome)" npm test
```

Для Chromium из Playwright выполните `npx playwright install chromium --only-shell`, затем `npm test`.
