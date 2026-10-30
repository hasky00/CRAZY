import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

// Collect declared dependencies from the common manifest files of our 5 languages.
export function collectDeps(dir) {
  const deps = [];
  const add = (ecosystem, name, version) => { if (name && version) deps.push({ ecosystem, name, version }); };

  const pkg = join(dir, "package.json");
  if (existsSync(pkg)) {
    try {
      const j = JSON.parse(readFileSync(pkg, "utf8"));
      for (const sec of ["dependencies", "devDependencies"])
        for (const [n, v] of Object.entries(j[sec] || {})) add("npm", n, String(v).replace(/^[\^~>=<\s]+/, ""));
    } catch {}
  }
  const req = join(dir, "requirements.txt");
  if (existsSync(req)) {
    for (const line of readFileSync(req, "utf8").split(/\r?\n/)) {
      const m = line.trim().match(/^([A-Za-z0-9_.\-\[\]]+)\s*==\s*([0-9][^\s;#]*)/);
      if (m) add("PyPI", m[1].replace(/\[.*\]/, ""), m[2]);
    }
  }
  const gomod = join(dir, "go.mod");
  if (existsSync(gomod)) {
    for (const line of readFileSync(gomod, "utf8").split(/\r?\n/)) {
      const m = line.trim().match(/^([a-zA-Z0-9.\-\/_]+)\s+v([0-9][^\s]*)/);
      if (m && m[1].includes("/")) add("Go", m[1], m[2]);
    }
  }
  const pom = join(dir, "pom.xml");
  if (existsSync(pom)) {
    const xml = readFileSync(pom, "utf8");
    const re = /<dependency>[\s\S]*?<groupId>([^<]+)<\/groupId>[\s\S]*?<artifactId>([^<]+)<\/artifactId>[\s\S]*?<version>([^<$]+)<\/version>/g;
    let m; while ((m = re.exec(xml))) add("Maven", `${m[1].trim()}:${m[2].trim()}`, m[3].trim());
  }
  const gradle = join(dir, "build.gradle");
  if (existsSync(gradle)) {
    const re = /['"]([a-zA-Z0-9.\-_]+):([a-zA-Z0-9.\-_]+):([0-9][^'"]*)['"]/g;
    let m; const txt = readFileSync(gradle, "utf8");
    while ((m = re.exec(txt))) add("Maven", `${m[1]}:${m[2]}`, m[3]);
  }
  const conan = join(dir, "conanfile.txt");
  if (existsSync(conan)) {
    for (const line of readFileSync(conan, "utf8").split(/\r?\n/)) {
      const m = line.trim().match(/^([a-zA-Z0-9_\-]+)\/([0-9][^\s@]*)/);
      if (m) add("ConanCenter", m[1], m[2]);
    }
  }
  return deps;
}

// Ask OSV (osv.dev) - the open vulnerability database used by Google, GitHub and others.
export async function checkDeps(deps) {
  if (!deps.length) return [];
  const out = [];
  for (let i = 0; i < deps.length; i += 500) {
    const batch = deps.slice(i, i + 500);
    const res = await fetch("https://api.osv.dev/v1/querybatch", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ queries: batch.map(d => ({ package: { name: d.name, ecosystem: d.ecosystem }, version: d.version })) }),
    });
    if (!res.ok) throw new Error(`OSV returned ${res.status}`);
    const j = await res.json();
    j.results.forEach((r, k) => {
      for (const v of r.vulns || []) out.push({ ...batch[k], id: v.id, modified: v.modified });
    });
  }
  return out;
}
