import { build } from 'esbuild';
import { readFileSync } from 'node:fs';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

const banner = `/*! ${pkg.name} v${pkg.version} | (c) 2026 Gregory J. Ward, CTO SmartLedger.Technology | MIT License | ${pkg.homepage || pkg.repository?.url || ''} */`;

const shared = {
  entryPoints: ['src/index.js'],
  bundle: true,
  target: ['es2020'],
  legalComments: 'none',
  banner: { js: banner },
};

await build({
  ...shared,
  format: 'esm',
  outfile: 'dist/mldsa.esm.js',
});

await build({
  ...shared,
  format: 'iife',
  globalName: 'MLDSA',
  outfile: 'dist/mldsa.js',
});

await build({
  ...shared,
  format: 'iife',
  globalName: 'MLDSA',
  minify: true,
  outfile: 'dist/mldsa.min.js',
});

console.log('Built dist/mldsa.esm.js, dist/mldsa.js, dist/mldsa.min.js');
