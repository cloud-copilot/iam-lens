import { loadPolicy, Statement } from '@cloud-copilot/iam-policy'
import { expandJsonDocument } from '@cloud-copilot/iam-expand'
import { IamCollectClient } from './collect/client.js'
import { getAllPoliciesForPrincipal } from './principals.js'

export interface SingleActionStatement {
  Effect: 'Allow' | 'Deny'
  Action: string
  Resource?: string
  NotResource?: string | string[]
  Condition?: any
}

export interface EffectivePolicyDocument {
  Version: '2012-10-17'
  Statement: SingleActionStatement[]
}

/**
 * Convert a list of iam-policy Condition objects to the raw JSON shape.
 */
function conditionsToObject(conds: any[]): any | undefined {
  if (!conds || conds.length === 0) {
    return undefined
  }
  const result: Record<string, any> = {}
  for (const cond of conds) {
    const op = (cond as any).op
    const key = (cond as any).key
    const values = (cond as any).values
    if (!result[op]) {
      result[op] = {}
    }
    result[op][key] = values
  }
  return result
}

async function extractStatements(policyDoc: any): Promise<SingleActionStatement[]> {
  const expanded = JSON.parse(JSON.stringify(policyDoc))
  await expandJsonDocument({ invertNotActions: true }, expanded)
  const policy = loadPolicy(expanded)
  const results: SingleActionStatement[] = []
  for (const stmt of policy.statements()) {
    const actions = (stmt as Statement).isActionStatement()
      ? (stmt as any).actions().map((a: any) => a.value())
      : ['*']
    const resources = (stmt as Statement).isResourceStatement()
      ? (stmt as any).resources().map((r: any) => r.value())
      : ['*']
    const notResources = (stmt as Statement).isNotResourceStatement()
      ? (stmt as any).notResources().map((r: any) => r.value())
      : []
    const condition = conditionsToObject((stmt as any).conditions())
    for (const action of actions) {
      if (resources.length === 0 && notResources.length === 0) {
        const statement: SingleActionStatement = {
          Effect: stmt.effect() as 'Allow' | 'Deny',
          Action: action,
          Resource: '*'
        }
        if (condition) {
          statement.Condition = condition
        }
        results.push(statement)
        continue
      }
      for (const resource of resources.length > 0 ? resources : ['*']) {
        const statement: SingleActionStatement = {
          Effect: stmt.effect() as 'Allow' | 'Deny',
          Action: action,
          Resource: resource
        }
        if (condition) {
          statement.Condition = condition
        }
        results.push(statement)
      }
      if (notResources.length > 0) {
        const statement: SingleActionStatement = {
          Effect: stmt.effect() as 'Allow' | 'Deny',
          Action: action,
          Resource: '*',
          NotResource: notResources.length === 1 ? notResources[0] : notResources
        }
        if (condition) {
          statement.Condition = condition
        }
        results.push(statement)
      }
    }
  }
  return results
}

function arnPatternsOverlap(a: string, b: string): boolean {
  if (a === '*' || b === '*') {
    return true
  }
  if (a === b) {
    return true
  }
  if (a.endsWith('*') && b.startsWith(a.slice(0, -1))) {
    return true
  }
  if (b.endsWith('*') && a.startsWith(b.slice(0, -1))) {
    return true
  }
  return false
}

function globMatch(pattern: string, value: string): boolean {
  if (pattern === '*') {
    return true
  }
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')
  const re = new RegExp(`^${escaped}$`)
  return re.test(value)
}

export function arnPatternMatches(pattern: string, candidate: string): boolean {
  return globMatch(pattern, candidate)
}

export function actionPatternMatches(pattern: string, action: string): boolean {
  return globMatch(pattern, action)
}

function resourceMatches(pattern: string, resource: string): boolean {
  return arnPatternMatches(pattern, resource)
}

function statementAppliesToResource(stmt: SingleActionStatement, resource: string): boolean {
  if (stmt.Resource) {
    return resourceMatches(stmt.Resource, resource)
  }
  if (stmt.NotResource) {
    const patterns = Array.isArray(stmt.NotResource) ? stmt.NotResource : [stmt.NotResource]
    return !patterns.some((p) => resourceMatches(p, resource))
  }
  return true
}

function invertConditionOperator(op: string): string | undefined {
  const map: Record<string, string> = {
    StringNotEquals: 'StringEquals',
    StringEquals: 'StringNotEquals',
    StringLike: 'StringNotLike',
    StringNotLike: 'StringLike',
    NumericEquals: 'NumericNotEquals',
    NumericNotEquals: 'NumericEquals',
    NumericLessThan: 'NumericGreaterThanEquals',
    NumericLessThanEquals: 'NumericGreaterThan',
    NumericGreaterThan: 'NumericLessThanEquals',
    NumericGreaterThanEquals: 'NumericLessThan',
    DateEquals: 'DateNotEquals',
    DateNotEquals: 'DateEquals',
    DateLessThan: 'DateGreaterThanEquals',
    DateLessThanEquals: 'DateGreaterThan',
    DateGreaterThan: 'DateLessThanEquals',
    DateGreaterThanEquals: 'DateLessThan',
    Bool: 'Bool',
    Null: 'Null'
  }
  return map[op]
}

function invertConditionBlock(cond: any): any | null {
  const result: Record<string, any> = {}
  for (const [op, val] of Object.entries(cond)) {
    const invertedOp = invertConditionOperator(op)
    if (!invertedOp) {
      return null
    }
    if (!result[invertedOp]) {
      result[invertedOp] = {}
    }
    for (const [key, value] of Object.entries(val as any)) {
      result[invertedOp][key] = value
    }
  }
  return result
}

function mergeConditionObjects(a: any, b: any): any {
  if (!a) {
    return JSON.parse(JSON.stringify(b))
  }
  for (const [op, val] of Object.entries(b)) {
    if (!a[op]) {
      a[op] = {}
    }
    for (const [key, value] of Object.entries(val as any)) {
      const existing = a[op][key]
      const values = Array.isArray(value) ? value : [value]
      if (!existing) {
        a[op][key] = values.length === 1 ? values[0] : values
      } else {
        const existingArr = Array.isArray(existing) ? existing : [existing]
        const merged = Array.from(new Set([...existingArr, ...values]))
        a[op][key] = merged.length === 1 ? merged[0] : merged
      }
    }
  }
  return a
}

function combineAllowConditions(stmts: SingleActionStatement[]): any | undefined {
  let result: any | undefined
  for (const s of stmts) {
    if (!s.Condition) {
      return undefined
    }
    result = mergeConditionObjects(result, s.Condition)
  }
  return result
}

/**
 * Calculate the effective policy for a principal by gathering all identity and
 * organizational policies. Resource policies are not currently included.
 */
export async function calculateEffectivePolicy(
  collectClient: IamCollectClient,
  principalArn: string
): Promise<EffectivePolicyDocument> {
  const principalPolicies = await getAllPoliciesForPrincipal(collectClient, principalArn)

  const identityPolicies: any[] = []
  identityPolicies.push(...principalPolicies.managedPolicies.map((p) => p.policy))
  identityPolicies.push(...principalPolicies.inlinePolicies.map((p) => p.policy))
  for (const group of principalPolicies.groupPolicies || []) {
    identityPolicies.push(...group.managedPolicies.map((p) => p.policy))
    identityPolicies.push(...group.inlinePolicies.map((p) => p.policy))
  }

  const identityStatements = (
    await Promise.all(identityPolicies.map((p) => extractStatements(p)))
  ).flat()
  const identityAllows = identityStatements.filter((s) => s.Effect === 'Allow')
  const identityDenies = identityStatements.filter((s) => s.Effect === 'Deny')

  let boundaryAllows: SingleActionStatement[] = []
  let boundaryDenies: SingleActionStatement[] = []
  if (principalPolicies.permissionBoundary) {
    const boundaryStmts = await extractStatements(principalPolicies.permissionBoundary.policy)
    boundaryAllows = boundaryStmts.filter((s) => s.Effect === 'Allow')
    boundaryDenies = boundaryStmts.filter((s) => s.Effect === 'Deny')
  }

  const scpLevels = await Promise.all(
    principalPolicies.scps.map(async (scpLevel) => {
      const stmts = (
        await Promise.all(scpLevel.policies.map((p) => extractStatements(p.policy)))
      ).flat()
      return {
        allows: stmts.filter((s) => s.Effect === 'Allow'),
        denies: stmts.filter((s) => s.Effect === 'Deny')
      }
    })
  )
  const scpDenies = scpLevels.flatMap((l) => l.denies)

  const rcpStatements = (
    await Promise.all(
      principalPolicies.rcps.flatMap((rcp) =>
        rcp.policies.map((p) => extractStatements(p.policy))
      )
    )
  ).flat()
  const rcpAllows = rcpStatements.filter((s) => s.Effect === 'Allow')
  const rcpDenies = rcpStatements.filter((s) => s.Effect === 'Deny')

  const allDenies = [...identityDenies, ...scpDenies, ...boundaryDenies, ...rcpDenies]

  const scopedIdentityAllows: SingleActionStatement[] = []
  for (const allow of identityAllows) {
    let combinedCond: any = allow.Condition ? JSON.parse(JSON.stringify(allow.Condition)) : undefined
    let allowed = true

    for (const level of scpLevels) {
      const matches = level.allows.filter(
        (scp) =>
          actionPatternMatches(scp.Action, allow.Action) &&
          statementAppliesToResource(scp, allow.Resource!)
      )
      if (matches.length === 0) {
        allowed = false
        break
      }
      const levelCond = combineAllowConditions(matches)
      if (levelCond) {
        combinedCond = mergeConditionObjects(combinedCond, levelCond)
      }
    }

    if (!allowed) {
      continue
    }

    if (boundaryAllows.length > 0) {
      const matches = boundaryAllows.filter(
        (pb) =>
          actionPatternMatches(pb.Action, allow.Action) &&
          statementAppliesToResource(pb, allow.Resource!)
      )
      if (matches.length === 0) {
        continue
      }
      const cond = combineAllowConditions(matches)
      if (cond) {
        combinedCond = mergeConditionObjects(combinedCond, cond)
      }
    }

    if (rcpAllows.length > 0) {
      const matches = rcpAllows.filter(
        (rcp) =>
          actionPatternMatches(rcp.Action, allow.Action) &&
          statementAppliesToResource(rcp, allow.Resource!)
      )
      if (matches.length === 0) {
        continue
      }
      const cond = combineAllowConditions(matches)
      if (cond) {
        combinedCond = mergeConditionObjects(combinedCond, cond)
      }
    }

    scopedIdentityAllows.push({ ...allow, Condition: combinedCond })
  }

  const finalAllows: SingleActionStatement[] = []
  for (const allow of scopedIdentityAllows) {
    const overlappingDenies = allDenies.filter((deny) => {
      if (!actionPatternMatches(deny.Action, allow.Action)) {
        return false
      }
      if (deny.Resource) {
        return arnPatternsOverlap(deny.Resource, allow.Resource!)
      }
      if (deny.NotResource) {
        const patterns = Array.isArray(deny.NotResource) ? deny.NotResource : [deny.NotResource]
        return !patterns.some((p) => arnPatternMatches(p, allow.Resource!))
      }
      return true
    })
    if (overlappingDenies.length === 0) {
      finalAllows.push(allow)
      continue
    }

    let combined: any = allow.Condition
    let dropAllow = false
    for (const deny of overlappingDenies) {
      if (!deny.Condition) {
        dropAllow = true
        break
      }
      const inverted = invertConditionBlock(deny.Condition)
      if (!inverted) {
        dropAllow = true
        break
      }
      combined = mergeConditionObjects(combined, inverted)
    }
    if (!dropAllow) {
      finalAllows.push({ ...allow, Condition: combined })
    }
  }

  return {
    Version: '2012-10-17',
    Statement: finalAllows
  }
}

