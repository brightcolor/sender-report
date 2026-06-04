const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const raw = execSync(
  'go list -deps -f "{{with .Module}}{{.Path}}|{{.Version}}|{{.Dir}}{{end}}" ./...',
  { encoding: "utf8", maxBuffer: 1 << 26 }
);

const seen = {};
const mods = [];
raw.split(/\r?\n/).forEach((l) => {
  l = l.trim();
  if (!l) return;
  const p = l.split("|");
  if (p.length < 3) return;
  const [mod, ver, dir] = p;
  if (mod === "github.com/brightcolor/sender-report") return;
  if (seen[mod]) return;
  seen[mod] = 1;
  mods.push({ mod, ver, dir });
});
mods.sort((a, b) => (a.mod < b.mod ? -1 : 1));

function findLicense(dir) {
  if (!dir || !fs.existsSync(dir)) return null;
  let names = fs.readdirSync(dir).filter((n) => /^(LICENSE|LICENCE|COPYING|NOTICE)(\.|$)/i.test(n));
  names.sort((a, b) => (/notice/i.test(a) ? 1 : 0) - (/notice/i.test(b) ? 1 : 0));
  if (!names.length) return null;
  try { return { name: names[0], text: fs.readFileSync(path.join(dir, names[0]), "utf8") }; }
  catch (e) { return null; }
}

const out = [];
const NL = "";
out.push("# Third-Party Notices");
out.push(NL);
out.push("sender.report is distributed as a single binary (and container image) that");
out.push("statically links the Go modules listed below. Their licenses (all permissive —");
out.push("MIT / BSD-3-Clause) are reproduced here as required by those licenses. Bundled");
out.push("frontend assets and their licenses are listed at the end.");
out.push(NL);
out.push("Regenerate with `node scripts/gen-third-party-notices.js` when dependencies change.");
out.push(NL);
out.push("---");
out.push(NL);

const missing = [];
mods.forEach((m) => {
  const lic = findLicense(m.dir);
  out.push("## " + m.mod + (m.ver ? " " + m.ver : ""));
  out.push(NL);
  if (lic) { out.push("```"); out.push(lic.text.replace(/\s+$/, "")); out.push("```"); }
  else { out.push("_License file not found in module cache._"); missing.push(m.mod); }
  out.push(NL);
});

out.push("---");
out.push(NL);
out.push("## Bundled frontend assets");
out.push(NL);
out.push("These files are shipped under `internal/web/static/vendor/` and retain their");
out.push("upstream license banners; their copyright and permission notices apply:");
out.push(NL);
out.push("| Asset | Version | License |");
out.push("|---|---|---|");
out.push("| Bootstrap | 5.3.x | MIT — Copyright The Bootstrap Authors |");
out.push("| Bootstrap Icons | 1.11.3 | MIT — Copyright The Bootstrap Authors |");
out.push("| AdminLTE | 4.0.0 | MIT — Copyright Colorlib |");
out.push("| Popper | 2.11.8 | MIT — Copyright Federico Zivolo and contributors |");
out.push("| OverlayScrollbars | 2.10.0 | MIT — Copyright Rene Haas, KingSora |");
out.push("| jsPDF | 2.5.1 | MIT — Copyright James Hall, yWorks GmbH and contributors |");
out.push("| TweetNaCl.js | — | Public domain, The Unlicense — Copyright Dmitry Chestnykh |");
out.push("| Inter (font) | — | SIL Open Font License 1.1 — see `internal/web/static/vendor/inter/LICENSE.txt` |");
out.push(NL);

fs.writeFileSync("THIRD_PARTY_NOTICES.md", out.join("\n") + "\n");
console.log("modules:", mods.length, "| missing:", missing.join(", ") || "none");
