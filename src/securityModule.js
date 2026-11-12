// Модуль Б (Кибербезопасность): проверка запроса, политика доступа, запись в блокчейн
const { ethers } = require("ethers");
const { ALLOWED_ISSUERS } = require("./config");
const { canon, sign } = require("./educationModule");

class SecurityModule {
  constructor(contract, monitor) {
    this.contract = contract; this.monitor = monitor;
    this.processed = new Map(); // opId -> результат (идемпотентность)
    this.down = false;          // флаг имитации отказа модуля
  }

  reject(msg, reason) {
    this.monitor.log("B:SEC", msg.opId, "REJECTED", { reason });
    this.monitor.alert(reason, msg.opId, { certId: msg.certId });
    const r = { opId: msg.opId, certId: msg.certId, status: "REJECTED", reason };
    this.processed.set(msg.opId, r);
    return r;
  }

  async handle(msg) {
    if (this.down) throw new Error("MODULE_B_UNAVAILABLE");
    this.monitor.log("B:SEC", msg.opId, "RECEIVED", { certId: msg.certId });

    if (this.processed.has(msg.opId)) {               // дубликат сообщения
      this.monitor.log("B:SEC", msg.opId, "DUPLICATE_IGNORED");
      this.monitor.alert("DUPLICATE_MESSAGE", msg.opId, { certId: msg.certId });
      return { ...this.processed.get(msg.opId), duplicate: true };
    }
    const { sig, ...rest } = msg;
    if (sig !== sign(rest)) return this.reject(msg, "BAD_SIGNATURE");            // целостность передачи
    const h = ethers.keccak256(ethers.toUtf8Bytes(canon(msg.payload)));
    if (h !== msg.hash || msg.payload.certId !== msg.certId)
      return this.reject(msg, "HASH_MISMATCH");                                   // несоответствие данных
    if (!ALLOWED_ISSUERS.includes(msg.payload.issuedBy))
      return this.reject(msg, "UNAUTHORIZED_ISSUER");                             // полномочия

    const opIdHex = ethers.id(msg.opId);
    if (await this.contract.usedOps(opIdHex)) {        // операция уже в блокчейне (восстановление)
      const r = { opId: msg.opId, certId: msg.certId, status: "ANCHORED", recovered: true };
      this.processed.set(msg.opId, r);
      this.monitor.log("B:SEC", msg.opId, "ALREADY_ON_CHAIN");
      return r;
    }
    const tx = await this.contract.issue(ethers.id(msg.certId), msg.hash, opIdHex);
    const rc = await tx.wait();
    const r = { opId: msg.opId, certId: msg.certId, status: "ANCHORED",
                txHash: rc.hash, block: rc.blockNumber, gas: rc.gasUsed.toString() };
    this.processed.set(msg.opId, r);
    this.monitor.log("B:SEC", msg.opId, "TX_CONFIRMED", { txHash: rc.hash, block: rc.blockNumber });
    return r;
  }
}
module.exports = { SecurityModule };
