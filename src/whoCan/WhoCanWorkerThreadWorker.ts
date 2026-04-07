// Worker thread entry point for whoCan simulations.
// Lifetime-scoped: a single PullBasedJobRunner is created at init and
// processes work items until 'finishWork' is received from the main thread.
import { type TopLevelConfig } from '@cloud-copilot/iam-collect'
import { parentPort, workerData } from 'worker_threads'
import { type ClientFactoryPlugin, getCollectClient } from '../collect/collect.js'
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
  collectGrantDetails,
  clientFactoryPlugin
} = workerData as {
  concurrency: number
  collectConfigs: TopLevelConfig[]
  partition: string
  s3AbacOverride: S3AbacOverride | undefined
  collectGrantDetails: boolean
  clientFactoryPlugin: ClientFactoryPlugin | undefined
}

/**
 * Properties threaded through the PullBasedJobRunner so onComplete
 * can recover the requestId for result routing.
 */
interface WorkerJobProperties {
  /** The request ID this job belongs to. */
  requestId: string

  /** Whether deny details should be collected for this work item's request. */
  collectDenyDetails: boolean
}

/**
 * Extended work item received from the main thread, includes requestId
 * so the worker can tag results and deny-detail messages.
 */
interface TaggedWorkerTask extends WhoCanWorkItem {
  /** The request ID this task belongs to. */
  requestId: string
}

// Pending task requests from workers, keyed by workerId
const taskPromises: Record<number, (val: any) => void> = {}

// Pending deny details checks, keyed by a unique id for each check
let denyDetailsCheckId = 0
const pendingDenyDetailsChecks: Record<number, (shouldInclude: boolean) => void> = {}

const collectClientPromise = getCollectClient(collectConfigs, partition, {
  cacheProvider: new SharedArrayBufferWorkerCache(parentPort),
  clientFactoryPlugin
})

/**
 * Creates the lifetime-scoped PullBasedJobRunner. The runner starts
 * immediately and processes work items until finishAllWork() is called.
 *
 * @returns the PullBasedJobRunner instance.
 */
function createJobRunner() {
  return new PullBasedJobRunner<WhoCanExecutionResult, WorkerJobProperties, TaggedWorkerTask>(
    concurrency,
    async (workerId) => {
      return new Promise((resolve) => {
        parentPort!.postMessage({ type: 'requestTask', workerId })
        taskPromises[workerId] = resolve
      })
    },
    (taggedTask) => {
      const { requestId, ...workItem } = taggedTask
      return {
        properties: { requestId, collectDenyDetails: workItem.collectDenyDetails },
        execute: async () => {
          const collectClient = await collectClientPromise
          return executeWhoCan(workItem, collectClient, {
            s3AbacOverride,
            collectDenyDetails: workItem.collectDenyDetails,
            collectGrantDetails,
            strictContextKeys: workItem.strictContextKeys
          })
        }
      }
    },
    async (result) => {
      const { requestId, collectDenyDetails } = result.properties

      if (result.status === 'fulfilled') {
        const executionResult = result.value

        if (executionResult.type === 'allowed') {
          parentPort!.postMessage({
            type: 'result',
            requestId,
            result: {
              status: 'fulfilled',
              value: executionResult.allowed,
              properties: {}
            }
          })
        } else {
          // Check if deny details check will follow
          const hasDetails =
            executionResult.type === 'denied_single' || executionResult.type === 'denied_wildcard'
          const denyDetailsCheckWillFollow = collectDenyDetails && hasDetails

          // Post count-only result for denied simulations
          parentPort!.postMessage({
            type: 'result',
            requestId,
            denyDetailsCheckWillFollow,
            result: {
              status: 'fulfilled',
              value: undefined,
              properties: {}
            }
          })

          if (denyDetailsCheckWillFollow) {
            const lightAnalysis = toLightRequestAnalysis(executionResult)
            const checkId = denyDetailsCheckId++

            parentPort!.postMessage({
              type: 'checkDenyDetails',
              requestId,
              checkId,
              workItem: executionResult.workItem,
              lightAnalysis
            })

            const shouldInclude = await new Promise<boolean>((resolve) => {
              pendingDenyDetailsChecks[checkId] = resolve
            })

            if (shouldInclude) {
              parentPort!.postMessage({
                type: 'denyDetailsResult',
                requestId,
                denyDetail: convertToDenialDetails(executionResult)
              })
            }
          }
        }
      } else {
        // Error case — pass through with requestId
        parentPort!.postMessage({
          type: 'result',
          requestId,
          result: result
        })
      }
    }
  )
}

// Create the lifetime-scoped runner immediately
const jobRunner = createJobRunner()

parentPort.on('message', (msg) => {
  if (msg.type === 'task' && msg.workerId in taskPromises) {
    // Task delivered from main thread (may be undefined if nothing is ready)
    taskPromises[msg.workerId](msg.task)
    delete taskPromises[msg.workerId]
  } else if (msg.type === 'workAvailable') {
    jobRunner.notifyWorkAvailable()
  } else if (msg.type === 'finishWork') {
    jobRunner.finishAllWork().then(() => {
      parentPort!.postMessage({ type: 'finished' })
    })
  } else if (msg.type === 'denyDetailsCheckResult') {
    const checkId = msg.checkId as number
    const resolveFn = pendingDenyDetailsChecks[checkId]
    if (resolveFn) {
      resolveFn(msg.shouldInclude)
      delete pendingDenyDetailsChecks[checkId]
    }
  }
})
