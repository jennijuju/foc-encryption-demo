import { defineConfig } from 'vite'
import { viteSingleFile } from 'vite-plugin-singlefile'

export default defineConfig({
  plugins: [viteSingleFile()],
  build: {
    assetsInlineLimit: Number.POSITIVE_INFINITY,
    outDir: 'dist',
    rollupOptions: {
      input: 'index.html',
    },
  },
})
