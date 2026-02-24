// src/workers/workerThread.ts
import { type TopLevelConfig } from '@cloud-copilot/iam-collect'
import { parentPort, workerData } from 'worker_threads'
import { getCollectClient } from '../collect/collect.js'
import { type S3AbacOverride } from '../utils/s3Abac.js'
import { PullBasedJobRunner } from '../workers/JobRunner.js'
import { SharedArrayBufferWorkerCache } from '../workers/SharedArrayBufferWorkerCache.js'
import { convertToDenialDetails, toLightRequestAnalysis } from './requestAnalysis.js'
import { executeWhoCan, type WhoCanExecutionResult, type WhoCanWorkItem } from './WhoCanWorker.js'

if (!parentPort) {
  throw new Error('Must be run as a worker thread')
}

// Get config from the main thread
const {
  concurrency,
  collectConfigs,
  partition,
  s3AbacOverride,
  collectDenyDetails,
  collectGrantDetails,
  strictContextKeys
} = workerData as {
  concurrency: number
  collectConfigs: TopLevelConfig[]
  partition: string
  s3AbacOverride: S3AbacOverride | undefined
  collectDenyDetails: boolean
  collectGrantDetails: boolean
  strictContextKeys: string[] | undefined
}

const taskPromises: Record<number, (val: any) => void> = {}

// Pending deny details checks - keyed by a unique id for each check
let denyDetailsCheckId = 0
const pendingDenyDetailsChecks: Record<number, (shouldInclude: boolean) => void> = {}

parentPort.on('message', (msg) => {
  if (msg.type === 'task' && msg.workerId in taskPromises) {
    taskPromises[msg.workerId](msg.task)
    delete taskPromises[msg.workerId]
  } else if (msg.type === 'workAvailable') {
    jobRunner.notifyWorkAvailable()
  } else if (msg.type === 'finishWork') {
    jobRunner.finishAllWork().then(() => {
      parentPort!.postMessage({ type: 'finished' })
    })
  } else if (msg.type === 'denyDetailsCheckResult') {
    // Handle response from main thread about whether to include deny details
    const checkId = msg.checkId as number
    const resolveFn = pendingDenyDetailsChecks[checkId]
    if (resolveFn) {
      resolveFn(msg.shouldInclude)
      delete pendingDenyDetailsChecks[checkId]
    }
  }
})

const collectClient = getCollectClient(collectConfigs, partition, {
  cacheProvider: new SharedArrayBufferWorkerCache(parentPort)
})

const jobRunner = new PullBasedJobRunner<
  WhoCanExecutionResult,
  Record<string, unknown>,
  WhoCanWorkItem
>(
  concurrency,
  async (workerId) => {
    return new Promise((resolve) => {
      parentPort!.postMessage({ type: 'requestTask', workerId })
      taskPromises[workerId] = resolve
    })
  },
  (taskDetails) => {
    return {
      properties: {},
      execute: async (context) => {
        return executeWhoCan(taskDetails, collectClient, {
          s3AbacOverride,
          collectDenyDetails,
          collectGrantDetails,
          strictContextKeys
        })
      }
    }
  },
  async (result) => {
    if (result.status === 'fulfilled') {
      const executionResult = result.value

      if (executionResult.type === 'allowed') {
        // Allowed - send result back to main thread
        parentPort!.postMessage({
          type: 'result',
          result: {
            status: 'fulfilled',
            value: executionResult.allowed,
            properties: result.properties
          }
        })
      } else {
        // Post this so that we can count the completed simulation in the main thread.
        parentPort!.postMessage({
          type: 'result',
          result: {
            status: 'fulfilled',
            value: undefined,
            properties: result.properties
          }
        })

        // Check if we should include deny details
        const hasDetails =
          executionResult.type === 'denied_single' || executionResult.type === 'denied_wildcard'

        if (collectDenyDetails && hasDetails) {
          const lightAnalysis = toLightRequestAnalysis(executionResult)
          const checkId = denyDetailsCheckId++

          // Send check request to main thread
          parentPort!.postMessage({
            type: 'checkDenyDetails',
            checkId,
            workItem: executionResult.workItem,
            lightAnalysis
          })

          // Wait for response from main thread
          const shouldInclude = await new Promise<boolean>((resolve) => {
            pendingDenyDetailsChecks[checkId] = resolve
          })

          if (shouldInclude) {
            // Get full denial reasons and send to main thread
            parentPort!.postMessage({
              type: 'denyDetailsResult',
              denyDetail: convertToDenialDetails(executionResult)
            })
          }
        }
      }
    } else {
      // Error case - pass through
      parentPort!.postMessage({ type: 'result', result })
    }
  }
)
