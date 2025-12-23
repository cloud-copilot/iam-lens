import { singleValueArgument } from '@cloud-copilot/cli'
import { existsSync, readFileSync } from 'fs'

export const stringOrFileArgument = singleValueArgument<string>((rawValue) => {
  try {
    return { valid: true, value: JSON.parse(rawValue) }
  } catch {
    // Not a JSON string, try to read as file
  }
  const fileExists = existsSync(rawValue)
  if (!fileExists) {
    return { valid: false, message: `Value is not valid JSON and file does not exist: ${rawValue}` }
  }

  const fileContents = readFileSync(rawValue, 'utf-8')
  try {
    const parsed = JSON.parse(fileContents)
    return { valid: true, value: parsed }
  } catch {}

  return { valid: false, message: `File contents are not valid JSON: ${rawValue}` }
}, '. A JSON string or a file path containing JSON.')
