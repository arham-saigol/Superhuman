import { copyFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const root = process.cwd();
const assets = join(root, 'assets');
const staticDir = join(root, 'vendor', 'open-webui', 'static');

if (!existsSync(staticDir)) {
  console.log('Open WebUI static folder not found; skipping branding.');
  process.exit(0);
}

const copies = [
  ['SuperhumanSymbolDark.png', 'favicon.png'],
  ['SuperhumanSymbolLight.png', 'favicon-dark.png'],
  ['SuperhumanLogoDark.png', 'splash.png']
];

for (const [src, dest] of copies) {
  copyFileSync(join(assets, src), join(staticDir, dest));
}

console.log('Applied Superhuman brand assets to Open WebUI static files.');
