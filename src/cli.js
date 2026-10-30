#!/usr/bin/env node
import { resolve } from "node:path";
import { writeFileSync } from "node:fs";
import { scanDir, score, RULES } from "./scan.js";
import { collectDeps, checkDeps } from "./deps.js";

const args = process.argv.slice(2);
const flags = new Set(args.filter(a => a.startsWith("--")));
const target = resolve(args.find(a => !a.startsWith("--")) || ".");

if (flags.has("--help") || flags.has("-h")) {
  console.log(`CRAZY - Critical Response Against Zero-day Yikes

Usage: crazy [directory] [options]

Options:
  --json          machine-readable output (for CI)
  --no-deps       skip the online dependency (OSV) check
  --finance-only  show only finance-pack findings
  --fail-on=SEV   exit 1 if any finding >= SEV (critical|high|medium|low). Default: high
  --out=FILE      also write the JSON report to FILE
  --rules         list all rules and exit

Every day is zero day. Scan every day.
Copyright Hasky Labs, Copenhagen. All rights reserved.`);
  process.exit(0);
}
if (flags.has("--rules")) {
  for (const r of RULES) console.log(`${r.id.padEnd(18)} ${r.sev.padEnd(9)} ${r.lang.padEnd(10)} ${r.msg}`);
  process.exit(0);
}

const SEV = ["critical", "high", "medium", "low"];
const COLOR = { critical: "\x1b[41m\x1b[97m", high: "\x1b[31m", medium: "\x1b[33m", low: "\x1b[36m" };
const R = "\x1b[0m", B = "\x1b[1m", D = "\x1b[2m";
const failOn = (args.find(a => a.startsWith("--fail-on=")) || "--fail-on=high").split("=")[1];
const outFile = (args.find(a => a.startsWith("--out=")) || "").split("=")[1];
const json = flags.has("--json");
const started = Date.now();

let { files, langs, findings } = scanDir(target);
if (flags.has("--finance-only")) findings = findings.filter(f => f.finance);

let vulns = [], depCount = 0, depError = null;
if (!flags.has("--no-deps")) {
  const deps = collectDeps(target);
  depCount = deps.length;
  try { vulns = await checkDeps(deps); } catch (e) { depError = e.message; }
}

const summary = Object.fromEntries(SEV.map(s => [s, findings.filter(f => f.sev === s).length]));
const report = {
  tool: "crazy", version: "0.1.0", target, scannedAt: new Date().toISOString(), ms: Date.now() - started,
  files, languages: langs, score: score(findings), summary, findings,
  dependencies: { checked: depCount, vulnerable: vulns.length, error: depError, vulns },
};
if (outFile) writeFileSync(outFile, JSON.stringify(report, null, 2));

if (json) {
  console.log(JSON.stringify(report, null, 2));
} else {
  console.log(`\n${B}CRAZY${R} ${D}Critical Response Against Zero-day Yikes${R}`);
  console.log(`${D}target:${R} ${target}`);
  console.log(`${D}files:${R}  ${files}  ${D}(${Object.entries(langs).map(([k, v]) => `${k} ${v}`).join(", ") || "no supported source files"})${R}\n`);
  for (const f of findings) {
    const tag = f.finance ? " \x1b[35m[FINANCE]\x1b[0m" : "";
    console.log(`${COLOR[f.sev]} ${f.sev.toUpperCase().padEnd(8)} ${R} ${f.file}:${f.line}  ${B}${f.rule}${R}${tag}`);
    console.log(`           ${f.msg} ${D}(${f.cwe})${R}`);
    console.log(`           ${D}${f.code}${R}`);
  }
  console.log(`\n${B}Dependencies:${R} ${depCount} checked, ${vulns.length ? COLOR.high : ""}${vulns.length} with known vulnerabilities${R}${depError ? `  ${D}(check failed: ${depError})${R}` : ""}`);
  for (const v of vulns) console.log(`  ${COLOR.high}VULN${R}  ${v.ecosystem} ${v.name}@${v.version}  ${v.id}  ${D}https://osv.dev/vulnerability/${v.id}${R}`);
  const sc = report.score;
  const scColor = sc >= 80 ? "\x1b[32m" : sc >= 50 ? "\x1b[33m" : "\x1b[31m";
  console.log(`\n${B}Findings:${R} ${SEV.map(s => `${s} ${summary[s]}`).join("  ")}`);
  console.log(`${B}Health score:${R} ${scColor}${sc}/100${R}  ${D}(${report.ms} ms)${R}`);
  console.log(`${D}Every day is zero day. Scan every day.${R}\n`);
}

const threshold = SEV.indexOf(failOn);
const bad = findings.some(f => SEV.indexOf(f.sev) <= threshold) || vulns.length > 0;
process.exit(bad ? 1 : 0);
