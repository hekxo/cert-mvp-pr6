// Общая конфигурация MVP
module.exports = {
  HMAC_KEY: process.env.HMAC_KEY || "edu-sec-shared-key-demo",
  ALLOWED_ISSUERS: ["dept.cybersecurity", "dept.blockchain"], // подразделения, которым разрешён выпуск
  OUTBOX_FILE: "logs/outbox.json",
  EVENTS_FILE: "logs/events.jsonl",
};
