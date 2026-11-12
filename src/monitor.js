// Мониторинг: единый журнал событий обоих модулей по opId + правила аномалий
const fs = require("fs");
const path = require("path");
const { EVENTS_FILE } = require("./config");

class Monitor {
  constructor() {
    this.events = []; this.alerts = [];
    fs.mkdirSync(path.dirname(EVENTS_FILE), { recursive: true });
    fs.writeFileSync(EVENTS_FILE, "");
  }
  log(module, opId, event, data = {}) {
    const e = { ts: new Date().toISOString(), module, opId, event, ...data };
    this.events.push(e);
    fs.appendFileSync(EVENTS_FILE, JSON.stringify(e) + "\n");
    return e;
  }
  alert(rule, opId, details) {
    const a = { ts: new Date().toISOString(), severity: "HIGH", rule, opId, details };
    this.alerts.push(a);
    this.log("MONITOR", opId, "ALERT", { rule, details });
  }
  trace(opId) { return this.events.filter(e => e.opId === opId); }

  // Правило межмодульной аномалии: расхождение статуса модуля А и состояния блокчейна
  async reconcile(eduModule, contract) {
    let mismatches = 0;
    for (const c of eduModule.db.values()) {
      const onChain = await contract.certs(c.certIdHex);
      const chainStatus = ["NONE", "ISSUED", "REVOKED"][Number(onChain.status)];
      const expected = c.status === "ISSUED" ? "ISSUED" : c.status === "REVOKED" ? "REVOKED" : "NONE";
      const hashOk = chainStatus === "NONE" || onChain.hash === c.hash;
      if (chainStatus !== expected || !hashOk) {
        mismatches++;
        this.alert("STATUS_MISMATCH", c.opId, { certId: c.certId, moduleA: c.status, chain: chainStatus, hashOk });
      }
    }
    return mismatches;
  }
}
module.exports = { Monitor };
