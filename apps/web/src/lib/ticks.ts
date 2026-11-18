/** "Clean" axis ticks: 0, step, 2·step… covering max with 3-5 ticks. */
export function niceTicks(max: number): number[] {
  if (!(max > 0)) return [0]
  const raw = max / 4
  const mag = 10 ** Math.floor(Math.log10(raw))
  const step = [1, 2, 2.5, 5, 10].map((m) => m * mag).find((s) => max / s <= 5) ?? 10 * mag
  const ticks: number[] = []
  for (let v = 0; v <= max + step * 0.001; v += step) ticks.push(Number(v.toFixed(10)))
  if (ticks[ticks.length - 1] < max) ticks.push(ticks[ticks.length - 1] + step)
  return ticks
}
