import { build } from 'esbuild';

const shared = {
  entryPoints: ['src/index.js'],
  bundle: true,
  target: ['es2020'],
  legalComments: 'none',
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
