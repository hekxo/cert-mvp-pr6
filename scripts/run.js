// Единая точка запуска: развёртывание -> демонстрация -> 6 приёмочных проверок -> 30 прогонов -> сверка
const hre = require("hardhat");
const fs = require("fs");
const { ethers } = hre;
const { Platform } = require("../src/platform");
const { sign } = require("../src/educationModule");

const STUDENTS = ["Иванов И.", "Петрова А.", "Ким Д.", "Ахметов Б.", "Смирнова Е."];
const sample = i => ({ student: STUDENTS[i % 5], course: "Blockchain Security", grade: 80 + (i % 20), issuedBy: "dept.cybersecurity" });
const pct = (arr, p) => { const s = [...arr].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.ceil(p / 100 * s.length) - 1)]; };
const line = t => console.log("\n=== " + t + " ===");

async function main() {
  const [admin, issuerB, outsider] = await ethers.getSigners();
  const Registry = await ethers.getContractFactory("CertificateRegistry");
  const registry = await Registry.deploy();
  await registry.waitForDeployment();
  await (await registry.setIssuer(issuerB.address, true)).wait();
  const contract = registry.connect(issuerB);   // модуль Б — единственный доверенный эмитент
  const P = new Platform(contract);
  line("DEPLOY");
  console.log("Contract:", await registry.getAddress(), "| issuer(Module B):", issuerB.address);

  // ---------- Демонстрация сквозного сценария ----------
  line("DEMO: A -> B -> blockchain -> A");
  const { msg, res } = await P.issueCertificate(sample(0));
  const st = await registry.certs(ethers.id(msg.certId));
  console.log("Module A request :", JSON.stringify({ opId: msg.opId, certId: msg.certId, hash: msg.hash }));
  console.log("Module B result  :", JSON.stringify(res));
  console.log("On-chain state   :", { status: Number(st.status), hash: st.hash });
  console.log("verify() on chain:", await registry.verify(ethers.id(msg.certId), msg.hash));
  console.log("Module A status  :", P.edu.db.get(msg.certId).status);
  console.log("Trace by opId    :"); P.monitor.trace(msg.opId).forEach(e => console.log("  ", e.module, e.event));

  // ---------- 6 приёмочных проверок ----------
  line("ACCEPTANCE TESTS");
  const tests = [];
  const T = (id, name, expected, actual, pass) => { tests.push({ id, name, expected, actual, pass }); console.log(`${id} ${pass ? "PASS" : "FAIL"} | ${name} | ${actual}`); };

  // AT-1 успешный процесс
  { const r = await P.issueCertificate(sample(1)); const ok = await registry.verify(ethers.id(r.msg.certId), r.msg.hash);
    T("AT-1", "Успешный сквозной процесс", "ANCHORED, verify=true, A=ISSUED", `${r.res.status}, verify=${ok}, A=${P.edu.db.get(r.msg.certId).status}`, r.res.status === "ANCHORED" && ok); }

  // AT-2 недопустимые полномочия (политика модуля Б + смарт-контракт)
  { const r = await P.issueCertificate({ ...sample(2), issuedBy: "dept.unknown" });
    let chainErr = "";
    try { await (await registry.connect(outsider).issue(ethers.id("X"), ethers.id("h"), ethers.id("op-x"))).wait(); } catch (e) { chainErr = e.shortMessage || e.message; }
    const blocked = chainErr.includes("NOT_ISSUER");
    T("AT-2", "Недопустимые полномочия", "REJECTED + revert NOT_ISSUER", `${r.res.status}/${r.res.reason}; chain: ${blocked ? "revert NOT_ISSUER" : chainErr}`, r.res.status === "REJECTED" && blocked); }

  // AT-3 дублирование сообщения
  { const r = await P.issueCertificate(sample(3)); const before = await ethers.provider.getBlockNumber();
    const d = await P.deliver(r.msg); const after = await ethers.provider.getBlockNumber();
    let chainErr = ""; try { await (await contract.issue(ethers.id("CERT-NEW"), r.msg.hash, ethers.id(r.msg.opId))).wait(); } catch (e) { chainErr = e.shortMessage || e.message; }
    T("AT-3", "Дублирование сообщения", "повтор не создаёт транзакцию, revert DUP_OP", `duplicate=${d.duplicate}, новых блоков=${after - before}, chain: ${chainErr.includes("DUP_OP") ? "revert DUP_OP" : chainErr}`, d.duplicate && after === before && chainErr.includes("DUP_OP")); }

  // AT-4 отказ модуля Б
  let pendingMsg;
  { P.sec.down = true; const r = await P.issueCertificate(sample(4)); pendingMsg = r.msg; P.sec.down = false;
    const st = await registry.certs(ethers.id(r.msg.certId));
    T("AT-4", "Отказ модуля Б", "PENDING в outbox, нет записи в блокчейне", `${r.res.status}, outbox=${P.outbox.get(r.msg.opId).state}, chain status=${st.status}`, r.res.status === "PENDING" && Number(st.status) === 0); }

  // AT-5 несоответствие данных (подмена оценки после расчёта хэша) + правило расхождения статусов
  { const m = P.edu.createCertificate(sample(5)); m.payload = { ...m.payload, grade: 100 }; const { sig, ...rest } = m; m.sig = sign(rest);
    const r = await P.deliver(m);
    const fake = P.edu.createCertificate(sample(6)); P.edu.db.get(fake.certId).status = "ISSUED"; // несанкционированное изменение в модуле А
    const mm = await P.monitor.reconcile(P.edu, registry);
    P.edu.db.get(fake.certId).status = "REJECTED"; P.edu.db.delete(fake.certId);
    T("AT-5", "Несоответствие данных", "HASH_MISMATCH + alert STATUS_MISMATCH", `${r.status}/${r.reason}; reconcile mismatches=${mm}`, r.reason === "HASH_MISMATCH" && mm === 1); }

  // AT-6 восстановление после сбоя (повтор из outbox + сбой после записи в блокчейн до подтверждения)
  { const r1 = await P.recover();
    const m = P.edu.createCertificate(sample(7)); P.outbox.set(m.opId, { msg: m, state: "PENDING" });
    await (await contract.issue(ethers.id(m.certId), m.hash, ethers.id(m.opId))).wait(); // tx прошла, ответ потерян
    P.sec.processed.clear();                                                                // перезапуск модуля Б
    const r2 = await P.recover();
    const all = [...r1, ...r2]; const mm = await P.monitor.reconcile(P.edu, registry);
    T("AT-6", "Восстановление после сбоя", "все PENDING -> ANCHORED, 0 расхождений", `${all.map(x => x.status + (x.recovered ? "(recovered)" : "")).join(", ")}; mismatches=${mm}`, all.every(x => x.status === "ANCHORED") && mm === 0); }

  // ---------- 30 повторных прогонов ----------
  line("LOAD: 30 runs");
  const lat = []; let ok = 0;
  for (let i = 0; i < 30; i++) {
    const t0 = process.hrtime.bigint();
    const r = await P.issueCertificate(sample(i));
    const v = await registry.verify(ethers.id(r.msg.certId), r.msg.hash);
    lat.push(Number(process.hrtime.bigint() - t0) / 1e6);
    if (r.res.status === "ANCHORED" && v && P.edu.db.get(r.msg.certId).status === "ISSUED") ok++;
  }
  const mismatches = await P.monitor.reconcile(P.edu, registry);
  const metrics = { runs: 30, success: ok, successRate: (ok / 30 * 100).toFixed(1) + "%", mismatches,
    p50_ms: pct(lat, 50).toFixed(2), p95_ms: pct(lat, 95).toFixed(2), min_ms: Math.min(...lat).toFixed(2), max_ms: Math.max(...lat).toFixed(2) };
  console.log(metrics);

  line("MONITORING SUMMARY");
  const byRule = {}; P.monitor.alerts.forEach(a => byRule[a.rule] = (byRule[a.rule] || 0) + 1);
  console.log("events:", P.monitor.events.length, "| alerts:", byRule);
  console.log("last block:", await ethers.provider.getBlockNumber());

  fs.mkdirSync("results", { recursive: true });
  fs.writeFileSync("results/results.json", JSON.stringify({ demo: { msg, res }, tests, metrics, latencies: lat, alerts: byRule, alertsList: P.monitor.alerts }, null, 2));
  console.log("\nResults saved to results/results.json, logs/events.jsonl, logs/outbox.json");
}
main().catch(e => { console.error(e); process.exit(1); });
