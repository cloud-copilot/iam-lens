export class RingQueue<T> {
  buffer: (T | undefined)[]
  head = 0
  tail = 0
  size: number
  capacity: number

  constructor(capacity: number) {
    this.capacity = capacity
    this.buffer = new Array(capacity)
    this.size = 0
  }

  enqueue(item: T): boolean {
    if (this.size >= this.capacity) return false

    this.buffer[this.tail] = item
    this.tail = (this.tail + 1) % this.capacity
    this.size++
    return true
  }

  dequeue(): T | undefined {
    if (this.size === 0) return undefined

    const item = this.buffer[this.head]
    this.buffer[this.head] = undefined
    this.head = (this.head + 1) % this.capacity
    this.size--
    return item
  }

  isEmpty(): boolean {
    return this.size === 0
  }

  length(): number {
    return this.size
  }

  isFull(): boolean {
    return this.size === this.capacity
  }
}
