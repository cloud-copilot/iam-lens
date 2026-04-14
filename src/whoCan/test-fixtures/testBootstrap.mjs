// Test bootstrap module for WhoCanProcessor bootstrap plugin tests.
// Records invocations so tests can verify the plugin was called correctly.
import { writeFileSync, mkdirSync } from 'fs'
import { dirname } from 'path'

/**
 * Bootstrap function that writes its invocation context to a file so
 * the test can verify it was called with the correct arguments.
 *
 * @param context - The bootstrap context.
 */
export async function testBootstrap(context) {
  const outputPath = context.data.outputPath
  mkdirSync(dirname(outputPath), { recursive: true })
  writeFileSync(
    outputPath,
    JSON.stringify({
      threadId: context.threadId,
      isMainThread: context.isMainThread,
      data: context.data,
      timestamp: Date.now()
    })
  )
}
