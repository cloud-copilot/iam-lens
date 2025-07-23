import { RingQueue } from './RingQueue.js'

export interface StreamingWorkQueueOptions {
  ringCapacity?: number
}

export class StreamingWorkQueue<T> {
  private ringCapacity = 1024
  private rings: RingQueue<T>[]
  private enqueueIndex = 0
  private dequeueIndex = 0
  private onWorkAvailable?: () => void
  private notifyScheduled = false

  constructor(options: StreamingWorkQueueOptions = {}) {
    if (options.ringCapacity) {
      this.ringCapacity = options.ringCapacity
    }
    this.rings = [new RingQueue<T>(this.ringCapacity)]
  }

  public setWorkAvailableCallback(callback: () => void): void {
    this.onWorkAvailable = callback
  }

  public enqueue(item: T): void {
    let attempts = 0
    while (attempts < this.rings.length) {
      const ring = this.rings[this.enqueueIndex]
      if (ring.enqueue(item)) {
        this.scheduleNotify()
        return
      }

      this.enqueueIndex = (this.enqueueIndex + 1) % this.rings.length
      attempts++
    }

    // All rings full, create a new one
    const newRing = new RingQueue<T>(this.ringCapacity)
    newRing.enqueue(item)
    this.rings.push(newRing)
    this.enqueueIndex = this.rings.length - 1
    this.scheduleNotify()
  }

  public dequeue(): T | undefined {
    let attempts = 0
    while (attempts < this.rings.length) {
      const ring = this.rings[this.dequeueIndex]
      const item = ring.dequeue()
      if (item !== undefined) return item

      this.dequeueIndex = (this.dequeueIndex + 1) % this.rings.length
      attempts++
    }

    return undefined
  }

  public length(): number {
    return this.rings.reduce((sum, ring) => sum + ring.length(), 0)
  }

  private scheduleNotify(): void {
    if (this.notifyScheduled || !this.onWorkAvailable) {
      return
    }

    this.notifyScheduled = true

    // Use a microtask to debounce notifications
    queueMicrotask(() => {
      this.notifyScheduled = false
      this.onWorkAvailable?.()
    })
  }
}
