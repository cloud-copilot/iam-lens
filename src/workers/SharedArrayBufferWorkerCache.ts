import { MessagePort } from 'worker_threads'
import { Cache } from './SharedArrayBufferMainCache.js'
import { convertArrayBufferToObject, convertObjectToArrayBuffer } from './buffers.js'

//TODO: Add a Prefix to avoid collisions if there are multiple caches
export class SharedArrayBufferWorkerCache implements Cache {
  private requestPromiseMap: Record<string, Promise<any> | undefined> = {}
  private parentPromiseMap: Record<string, (value: SharedArrayBuffer | false) => void> = {}

  constructor(private parentPort: MessagePort) {
    this.parentPort.on('message', (msg) => {
      // console.log('Received message in worker cache:', msg)
      if (msg.type === 'cacheHit' || msg.type === 'cacheMiss') {
        const resolver = this.parentPromiseMap[msg.cacheKey]
        if (resolver) {
          delete this.parentPromiseMap[msg.cacheKey] // clean up
          resolver(msg.type === 'cacheHit' ? msg.value : false)
        }
      }
    })
  }

  async withCache<T>(cacheKey: string, fetcher: () => Promise<T>): Promise<T> {
    if (this.requestPromiseMap[cacheKey]) {
      return this.requestPromiseMap[cacheKey]
    }

    this.requestPromiseMap[cacheKey] = (async () => {
      try {
        const parentPromise = new Promise<SharedArrayBuffer | false>((resolve) => {
          this.parentPromiseMap[cacheKey] = resolve
          // console.log('Requesting cacheKey from worker thread:', cacheKey)
          this.parentPort.postMessage({ type: 'getCache', cacheKey })
        })

        const response = await parentPromise

        if (response === false) {
          const theValue = await fetcher() // your async loader
          const arrayBuffer = convertObjectToArrayBuffer(theValue)
          this.parentPort.postMessage({ type: 'saveCache', cacheKey, value: arrayBuffer })
          return theValue
        }

        return convertArrayBufferToObject(response)
      } finally {
        delete this.requestPromiseMap[cacheKey] // Clean up the queue regardless of success or failure.
      }
    })()

    return this.requestPromiseMap[cacheKey]
  }
}
