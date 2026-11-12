# MVP: Реестр цифровых сертификатов (Образование + Кибербезопасность)

Модуль А (src/educationModule.js) формирует сертификат и подписанный запрос.
Модуль Б (src/securityModule.js) проверяет подпись, хэш, полномочия и записывает сертификат в смарт-контракт.
Интеграция: src/platform.js (outbox, повторная доставка), мониторинг: src/monitor.js.

## Запуск
    npm install
    npm start

Результаты: results/results.json, журнал событий logs/events.jsonl, outbox logs/outbox.json.
