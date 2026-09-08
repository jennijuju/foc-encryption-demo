import { build } from 'esbuild'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'

const packageRoot = fileURLToPath(new URL('..', import.meta.url))

await build({
  entryPoints: [join(packageRoot, 'src', 'protect-cli.ts')],
  outfile: join(packageRoot, 'dist', 'foc-protect.mjs'),
  alias: {
    'foc-encryption': join(packageRoot, '..', 'foc-encryption', 'src', 'index.ts'),
  },
  bundle: true,
  format: 'esm',
  platform: 'node',
  target: 'node20',
  treeShaking: true,
  legalComments: 'none',
})
