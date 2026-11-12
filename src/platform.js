// Интеграционный контур: outbox, автоматическая передача A -> B -> блокчейн -> A
const fs = require("fs");
const { OUTBOX_FILE } = require("./config");
const { Monitor } = require("./monitor");
const { EducationModule } = require("./educationModule");
const { SecurityModule } = require("./securityModule");

class Platform {
  constructor(contract) {
    this.monitor = new Monitor();
    this.edu = new EducationModule(this.monitor);
    this.sec = new SecurityModule(contract, this.monitor);
    this.contract = contract;
    this.outbox = new Map();
    fs.writeFileSync(OUTBOX_FILE, "[]");
  }
  saveOutbox() { fs.writeFileSync(OUTBOX_FILE, JSON.stringify([...this.outbox.values()], null, 1)); }

  async deliver(msg) {
    if (!this.outbox.has(msg.opId)) { this.outbox.set(msg.opId, { msg, state: "PENDING" }); this.saveOutbox(); }
    try {
      const res = await this.sec.handle(msg);
      this.edu.onResult(res);
      this.outbox.get(msg.opId).state = "DONE"; this.saveOutbox();
      return res;
    } catch (e) {
      this.monitor.log("PLATFORM", msg.opId, "DELIVERY_FAILED", { error: e.shortMessage || e.message });
      return { opId: msg.opId, certId: msg.certId, status: "PENDING", error: e.message };
    }
  }

  async issueCertificate(data) {            // единая точка входа пользователя
    const msg = this.edu.createCertificate(data);
    return { msg, res: await this.deliver(msg) };
  }

  async recover() {                         // повторная доставка незавершённых операций
    const out = [];
    for (const { msg, state } of [...this.outbox.values()])
      if (state === "PENDING") { this.monitor.log("PLATFORM", msg.opId, "RETRY"); out.push(await this.deliver(msg)); }
    return out;
  }
}
module.exports = { Platform };
