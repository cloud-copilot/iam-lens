import { RequestAnalysis } from '@cloud-copilot/iam-simulate'

/**
 * A light version of RequestAnalysis containing only the result and sameAccount fields,
 * along with the result fields of the various analyses.
 */
export interface LightRequestAnalysis {
  result: RequestAnalysis['result']
  sameAccount: RequestAnalysis['sameAccount']
  identityAnalysis?: Pick<NonNullable<RequestAnalysis['identityAnalysis']>, 'result'>
  resourceAnalysis?: Pick<NonNullable<RequestAnalysis['resourceAnalysis']>, 'result'>
  scpAnalysis?: Pick<NonNullable<RequestAnalysis['scpAnalysis']>, 'result'>
  rcpAnalysis?: Pick<NonNullable<RequestAnalysis['rcpAnalysis']>, 'result'>
  permissionBoundaryAnalysis?: Pick<
    NonNullable<RequestAnalysis['permissionBoundaryAnalysis']>,
    'result'
  >
}

/**
 * Convert a full RequestAnalysis to a LightRequestAnalysis
 *
 * @param analysis the full RequestAnalysis to convert
 * @returns a LightRequestAnalysis with only the essential fields
 */
export function toLightRequestAnalysis(analysis: RequestAnalysis): LightRequestAnalysis {
  return {
    result: analysis.result,
    sameAccount: analysis.sameAccount,
    identityAnalysis: analysis.identityAnalysis
      ? { result: analysis.identityAnalysis.result }
      : undefined,
    resourceAnalysis: analysis.resourceAnalysis
      ? { result: analysis.resourceAnalysis.result }
      : undefined,
    scpAnalysis: analysis.scpAnalysis ? { result: analysis.scpAnalysis.result } : undefined,
    rcpAnalysis: analysis.rcpAnalysis ? { result: analysis.rcpAnalysis.result } : undefined,
    permissionBoundaryAnalysis: analysis.permissionBoundaryAnalysis
      ? { result: analysis.permissionBoundaryAnalysis.result }
      : undefined
  }
}
