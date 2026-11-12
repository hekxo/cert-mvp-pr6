// Модуль А (Образование): формирование сертификата и запроса на регистрацию
const crypto = require("crypto");
const { ethers } = require("ethers");
const { HMAC_KEY } = require("./config");

const canon = o => JSON.stringify(o, Object.keys(o).sort());
const sign = msg => crypto.createHmac("sha256", HMAC_KEY)
  .update(canon({ ...msg, payload: canon(msg.payload) })).digest("hex");

class EducationModule {
  constructor(monitor) { this.db = new Map(); this.monitor = monitor; }

  createCertificate({ student, course, grade, issuedBy }) {
    const certId = "CERT-" + crypto.randomUUID().slice(0, 8).toUpperCase();
    const opId = crypto.randomUUID();
    const payload = { certId, student, course, grade, issuedBy };
    const hash = ethers.keccak256(ethers.toUtf8Bytes(canon(payload)));
    const msg = { version: 1, type: "CERT_ISSUE_REQUEST", opId, certId, payload, hash, ts: Date.now() };
    msg.sig = sign(msg);
    this.db.set(certId, { certId, certIdHex: ethers.id(certId), opId, hash, payload, status: "PENDING" });
    this.monitor.log("A:EDU", opId, "CERT_CREATED", { certId, hash });
    return msg;
  }

  onResult(res) { // приём результата из модуля Б
    const c = this.db.get(res.certId);
    if (!c) return;
    if (res.status === "ANCHORED") c.status = "ISSUED";
    else if (res.status === "REJECTED") c.status = "REJECTED";
    if (res.txHash) c.txHash = res.txHash;
    this.monitor.log("A:EDU", res.opId, "STATUS_UPDATED", { certId: res.certId, status: c.status });
  }
}
module.exports = { EducationModule, canon, sign };
