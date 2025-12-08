export const S3AbacOverrideOptions = ['enabled', 'disabled'] as const

export type S3AbacOverride = (typeof S3AbacOverrideOptions)[number]
