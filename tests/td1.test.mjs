// Design language TD-1 (silexi/portfolio docs/tasarim-dili.md): static checks on public/.
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import assert from "node:assert/strict";

const walk = (d) => readdirSync(d).flatMap((n) => (statSync(join(d, n)).isDirectory() ? walk(join(d, n)) : [join(d, n)]));
const files = walk("public");
for (const f of files.filter((f) => f.endsWith(".css"))) {
  const css = readFileSync(f, "utf8");
  for (const m of css.matchAll(/font(?:-size)?:\s*([\d.]+)(px|rem)/g)) {
    const px = m[2] === "rem" ? parseFloat(m[1]) * 16 : parseFloat(m[1]);
    assert.ok(px >= 13, `font size below 13px in ${f}: ${m[0]}`);
  }
}
for (const f of files.filter((f) => f.endsWith(".html"))) {
  const vp = (readFileSync(f, "utf8").match(/<meta name="viewport" content="([^"]*)"/) || [])[1];
  assert.ok(vp && vp.includes("width=device-width") && !/user-scalable\s*=\s*no|maximum-scale/.test(vp), `viewport: ${f}`);
}
// Text and muted text at least 7:1 on the page background, both themes, in every stylesheet that defines them.
const lum = (hex) => { const c = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((x) => (x <= 0.04045 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4)); return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]; };
const ratio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };
for (const f of ["public/css/style.css"]) {
  const css = readFileSync(f, "utf8");
  assert.match(css, /--td:\s*"TD-1"/, `TD-1 version line missing: ${f}`);
  const [light, dark] = css.split(/@media \(prefers-color-scheme: ?dark\)/);
  for (const [theme, block] of [["light", light], ["dark", dark]]) {
    const v = (k) => (block.match(new RegExp(`--${k}:\\s*(#[0-9a-f]{6})`, "i")) || [])[1];
    for (const role of ["fg", "mute"]) {
      const c = ratio(v(role), v("bg"));
      assert.ok(c >= 7, `${f} ${theme} --${role} on --bg is ${c.toFixed(2)}:1, needs 7:1`);
    }
  }
}
console.log("ok: TD-1 static checks");
