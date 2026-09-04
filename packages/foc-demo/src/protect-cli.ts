import { createWriteStream } from 'node:fs'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { parseArgs } from 'node:util'
import { protectPath } from './protect.js'

function parseInheritedFd(value: string | undefined, flag: string): number | undefined {
  if (value === undefined) return undefined
  if (!/^\d+$/.test(value)) throw new Error(`${flag} must be an inherited file descriptor`)
  const fd = Number(value)
  if (!Number.isSafeInteger(fd) || fd < 3) {
    throw new Error(`${flag} must be an inherited file descriptor numbered 3 or higher`)
  }
  return fd
}

export async function main(args: string[] = process.argv.slice(2)): Promise<void> {
  const { values } = parseArgs({
    args,
    allowPositionals: false,
    strict: true,
    options: {
      input: { type: 'string' },
      output: { type: 'string' },
      'access-key-output-fd': { type: 'string' },
    },
  })

  if (!values.input || !values.output) throw new Error('--input and --output are required')
  const accessKeyOutputFd = parseInheritedFd(values['access-key-output-fd'], '--access-key-output-fd')
  if (accessKeyOutputFd === undefined) {
    throw new Error('--access-key-output-fd is required')
  }

  const accessKeyOutput = createWriteStream('', { fd: accessKeyOutputFd })
  try {
    const result = await protectPath({
      input: values.input,
      output: values.output,
      accessKeyOutput,
    })
    process.stdout.write(`${JSON.stringify(result)}\n`)
  } finally {
    accessKeyOutput.end()
  }
}

const entryPath = process.argv[1]
if (entryPath && import.meta.url === pathToFileURL(resolve(entryPath)).href) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : 'Protection failed'}\n`)
    process.exitCode = 1
  })
}
