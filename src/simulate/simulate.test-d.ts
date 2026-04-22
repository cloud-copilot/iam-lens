import type { RunSimulationResults, Simulation } from '@cloud-copilot/iam-simulate'
import { describe, expectTypeOf, it } from 'vitest'
import type { SimulateRequestResult } from './simulate.js'

describe('SimulateRequestResult type contract', () => {
  it('should have a result field that is RunSimulationResults', () => {
    expectTypeOf<SimulateRequestResult['result']>().toEqualTypeOf<RunSimulationResults>()
  })

  it('should have a request field that is Simulation request', () => {
    expectTypeOf<SimulateRequestResult['request']>().toEqualTypeOf<Simulation['request']>()
  })
})
