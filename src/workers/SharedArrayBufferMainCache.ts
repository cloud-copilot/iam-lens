import { Worker } from 'worker_threads'
import { convertArrayBufferToObject, convertObjectToArrayBuffer } from './buffers.js'

export interface Cache {
  withCache<T>(cacheKey: string, fetcher: () => Promise<T>): Promise<T>
}
//TODO: Add a Prefix to avoid collisions if there are multiple caches
export class SharedArrayBufferMainCache implements Cache {
  private cache: Record<string, SharedArrayBuffer> = {}

  constructor(workers: Worker[]) {
    for (const worker of workers) {
      worker.on('message', (message) => {
        if (message.type === 'getCache') {
          const cacheKey = message.cacheKey
          const value = this.cache[cacheKey]
          if (value) {
            worker.postMessage({ type: 'cacheHit', cacheKey, value })
          } else {
            worker.postMessage({ type: 'cacheMiss', cacheKey })
          }
        } else if (message.type === 'saveCache') {
          this.cache[message.cacheKey] = message.value
        }
      })
    }
  }

  async withCache<T>(cacheKey: string, fetcher: () => Promise<T>): Promise<T> {
    if (this.cache[cacheKey]) {
      return convertArrayBufferToObject(this.cache[cacheKey])
    }

    const result = await fetcher()
    this.cache[cacheKey] = convertObjectToArrayBuffer(result)
    return result
  }
}
