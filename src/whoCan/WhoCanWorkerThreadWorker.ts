// src/workers/workerThread.ts
import { TopLevelConfig } from '@cloud-copilot/iam-collect'
import { parentPort, workerData } from 'worker_threads'
import { getCollectClient } from '../collect/collect.js'
import { PullBasedJobRunner } from '../workers/JobRunner.js'
import { SharedArrayBufferWorkerCache } from '../workers/SharedArrayBufferWorkerCache.js'
import { executeWhoCan, WhoCanWorkItem } from './WhoCanWorker.js'
import { WhoCanAllowed } from './whoCan.js'

if (!parentPort) {
  throw new Error('Must be run as a worker thread')
}

// Get config from the main thread
const { concurrency, collectConfigs, partition } = workerData as {
  concurrency: number
  collectConfigs: TopLevelConfig[]
  partition: string
}

// console.log(JSON.stringify(workerData))

const taskPromises: Record<number, (val: any) => void> = {}

parentPort.on('message', (msg) => {
  if (msg.type === 'task' && msg.workerId in taskPromises) {
    taskPromises[msg.workerId](msg.task)
    delete taskPromises[msg.workerId]
  } else if (msg.type === 'workAvailable') {
    jobRunner.notifyWorkAvailable()
  } else if (msg.type === 'finishWork') {
    // console.log('Worker received finishWork message')
    jobRunner.finishAllWork().then(() => {
      // console.log('Worker finished all work, sending finished message')
      parentPort!.postMessage({ type: 'finished' })
      // new Promise((resolve) => {
      //   setTimeout(() => {
      //     console.log(
      //       `Worker exiting. Requests: ${requestCount}, Tasks: ${taskCount}, Returns: ${returnCount}`
      //     )

      //     parentPort!.postMessage({ type: 'finished' })
      //   }, 2000)
      // })
    })
  }
})

const collectClient = getCollectClient(collectConfigs, partition, {
  cacheProvider: new SharedArrayBufferWorkerCache(parentPort)
})

const jobRunner = new PullBasedJobRunner<
  WhoCanAllowed | undefined,
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
    // console.log(`Worker creating job for task: ${JSON.stringify(taskDetails)}`)
    // return createJobForWhoCanWorkItem(taskDetails, collectClient)
    return {
      properties: {},
      execute: async (context) => {
        // console.log(`Worker executing job for task: ${JSON.stringify(taskDetails)}`)
        return executeWhoCan(taskDetails, collectClient)
      }
    }
  },
  async (result) => {
    // console.log('Worker posting result back to main thread', result)
    parentPort!.postMessage({ type: 'result', result })
  }
)
