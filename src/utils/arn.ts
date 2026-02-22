import { type ArnParts, splitArnParts } from '@cloud-copilot/iam-utils'

export class Arn {
  private readonly parts: ArnParts

  constructor(private readonly arn: string) {
    this.parts = splitArnParts(arn)
  }

  get service(): string {
    return this.parts.service!
  }

  get partition(): string {
    return this.parts.partition!
  }

  get region(): string | undefined {
    return this.parts.region
  }

  get accountId(): string | undefined {
    return this.parts.accountId
  }

  get resourceType(): string | undefined {
    return this.parts.resourceType
  }

  get resourcePath(): string | undefined {
    return this.parts.resourcePath
  }

  get resource(): string {
    return this.parts.resource || ''
  }

  get value(): string {
    return this.arn
  }

  /**
   * Check
   *
   * @param parts
   * @returns
   */
  matches(parts: Partial<ArnParts>): boolean {
    return Object.entries(parts).every(([key, value]) => {
      return this.parts[key as keyof ArnParts] === value
    })
  }
}
