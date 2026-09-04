import { Buffer } from 'node:buffer'
import { createReadStream, createWriteStream } from 'node:fs'
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

async function readPassword(fd: number): Promise<string> {
  const input = createReadStream('', { fd })
  const decoder = new TextDecoder('utf-8', { fatal: true })
  let password = ''
  for await (const chunk of input) {
    const bytes = chunk instanceof Uint8Array ? chunk : Buffer.from(String(chunk))
    password += decoder.decode(bytes, { stream: true })
  }
  password += decoder.decode()
  password = password.replace(/\r?\n$/, '')
  if (!password) throw new Error('Password input must not be empty')
  return password
}

export async function main(args: string[] = process.argv.slice(2)): Promise<void> {
  const { values } = parseArgs({
    args,
    allowPositionals: false,
    strict: true,
    options: {
      input: { type: 'string' },
      output: { type: 'string' },
      'password-input-fd': { type: 'string' },
      'password-output-fd': { type: 'string' },
    },
  })

  if (!values.input || !values.output) throw new Error('--input and --output are required')
  const passwordInputFd = parseInheritedFd(values['password-input-fd'], '--password-input-fd')
  const passwordOutputFd = parseInheritedFd(values['password-output-fd'], '--password-output-fd')
  if ((passwordInputFd === undefined) === (passwordOutputFd === undefined)) {
    throw new Error('Provide exactly one of --password-input-fd or --password-output-fd')
  }

  const password = passwordInputFd === undefined ? undefined : await readPassword(passwordInputFd)
  const passwordOutput = passwordOutputFd === undefined ? undefined : createWriteStream('', { fd: passwordOutputFd })
  try {
    const result = await protectPath({
      input: values.input,
      output: values.output,
      password,
      passwordOutput,
    })
    process.stdout.write(`${JSON.stringify(result)}\n`)
  } finally {
    passwordOutput?.end()
  }
}

const entryPath = process.argv[1]
if (entryPath && import.meta.url === pathToFileURL(resolve(entryPath)).href) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : 'Protection failed'}\n`)
    process.exitCode = 1
  })
}
