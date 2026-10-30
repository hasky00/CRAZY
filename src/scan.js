import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, extname, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
export const RULES = JSON.parse(readFileSync(join(__dirname, "..", "rules", "rules.json"), "utf8"))
  .map(r => ({ ...r, re: new RegExp(r.pattern.replace(/^\(\?i\)/, ""), r.pattern.startsWith("(?i)") ? "i" : "") }));

export const LANG_BY_EXT = {
  ".py": "python",
  ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
  ".ts": "javascript", ".tsx": "javascript",
  ".java": "java", ".kt": "java",
  ".c": "c", ".h": "c", ".cc": "c", ".cpp": "c", ".cxx": "c", ".hpp": "c",
  ".go": "go",
};

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", "vendor", "target", ".venv", "venv", "__pycache__", ".next", "coverage"]);
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

export function* walk(dir, root = dir) {
  for (const name of readdirSync(dir)) {
    if (SKIP_DIRS.has(name)) continue;
    const full = join(dir, name);
    let st;
    try { st = statSync(full); } catch { continue; }
    if (st.isDirectory()) yield* walk(full, root);
    else if (st.size < 2_000_000) yield { full, rel: relative(root, full), ext: extname(name).toLowerCase() };
  }
}

export function scanFile(file) {
  const lang = LANG_BY_EXT[file.ext];
  if (!lang) return [];
  let text;
  try { text = readFileSync(file.full, "utf8"); } catch { return []; }
  const lines = text.split(/\r?\n/);
  const findings = [];
  const applicable = RULES.filter(r => r.lang === lang || r.lang === "any");
  lines.forEach((line, i) => {
    if (line.length > 2000) return; // minified / generated
    for (const r of applicable) {
      if (r.re.test(line)) {
        findings.push({ rule: r.id, sev: r.sev, cwe: r.cwe, finance: !!r.finance, msg: r.msg,
          file: file.rel, line: i + 1, code: line.trim().slice(0, 160) });
      }
    }
  });
  return findings;
}

export function scanDir(dir) {
  const findings = [];
  let files = 0;
  const langs = {};
  for (const f of walk(dir)) {
    const lang = LANG_BY_EXT[f.ext];
    if (!lang) continue;
    files++;
    langs[lang] = (langs[lang] || 0) + 1;
    findings.push(...scanFile(f));
  }
  findings.sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev] || a.file.localeCompare(b.file) || a.line - b.line);
  return { files, langs, findings };
}

export function score(findings) {
  // 100 = clean. Each severity costs points; finance findings cost double.
  const cost = { critical: 25, high: 10, medium: 4, low: 1 };
  let s = 100;
  for (const f of findings) s -= cost[f.sev] * (f.finance ? 2 : 1);
  return Math.max(0, s);
}
