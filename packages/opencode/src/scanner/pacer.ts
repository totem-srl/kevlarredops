export type Pacer = () => Promise<void>

export function createPacer(rps: number): Pacer {
  const minDelay = 1000 / Math.max(rps, 0.1)
  let last = 0
  return async () => {
    const wait = last + minDelay - Date.now()
    if (wait > 0) await new Promise((resolve) => setTimeout(resolve, wait))
    last = Date.now()
  }
}
