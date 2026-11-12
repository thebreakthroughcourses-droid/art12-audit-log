import { AuditLogger, AuditLogReader } from './aiact-audit-log/dist/index.js'
import { mkdtempSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
const N = 10000
const dir = mkdtempSync(join(tmpdir(), 'systima-'))
const cfg = { systemId: 'bench', storage: { type: 'filesystem', directory: dir }, integrity: { hmacKey: 'bench-key' } }
const logger = new AuditLogger(cfg)
let t = performance.now()
for (let i = 0; i < N; i++) {
  await logger.log({ decisionId: `B${i}`, eventType: 'inference', modelId: 'm', providerId: 'p',
    input: { value: `applicant p${i}` }, output: { value: 'score 0.5' }, latencyMs: 5,
    parameters: { t: 0.7 }, error: null })
}
await logger.close()
const writeS = (performance.now() - t) / 1000
const reader = new AuditLogReader({ systemId: 'bench', storage: cfg.storage, integrity: cfg.integrity })
t = performance.now()
const r = await reader.verifyChain()
const verifyS = (performance.now() - t) / 1000
function size(p){ let s=0; for (const f of readdirSync(p,{withFileTypes:true})) { const q=join(p,f.name); s += f.isDirectory()? size(q): statSync(q).size } return s }
const bytes = size(dir)
console.log(`entries              ${N}`)
console.log(`write (batched 100)  ${writeS.toFixed(2)}s -> ${Math.round(N/writeS).toLocaleString()} entries/s`)
console.log(`full verify          ${verifyS.toFixed(2)}s  result=${JSON.stringify(r).slice(0,120)}`)
console.log(`disk                 ${(bytes/1e6).toFixed(1)} MB (${Math.round(bytes/N)} bytes/entry)`)
