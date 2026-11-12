import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['src/index.ts', 'src/admin.ts', 'src/rest.ts'],
  format: ['esm'],
  dts: true,
  clean: true,
  sourcemap: true,
  target: 'es2022',
  removeNodeProtocol: false,
  external: [/^@ghuri\//, /^node:/, 'hono'],
})
