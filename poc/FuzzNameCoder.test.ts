import hre from 'hardhat'
import { keccak256, concat, toHex } from 'viem'

const connection = await hre.network.connect()

async function fixture() {
  return connection.viem.deployContract('TestNameCoder', [])
}
const loadFixture = async () => connection.networkHelpers.loadFixture(fixture)

// Reference namehash operating on raw label byte-arrays (ENS spec, no normalization).
function refNamehash(labels: Uint8Array[]): `0x${string}` {
  let node = ('0x' + '00'.repeat(32)) as `0x${string}`
  for (let i = labels.length - 1; i >= 0; i--) {
    const lh = keccak256(toHex(labels[i]))
    node = keccak256(concat([node, lh]))
  }
  return node
}

// DNS-encode a list of raw label byte-arrays: <len><label>...<0x00>
function dnsEncode(labels: Uint8Array[]): `0x${string}` {
  const parts: Uint8Array[] = []
  for (const l of labels) {
    parts.push(Uint8Array.from([l.length]))
    parts.push(l)
  }
  parts.push(Uint8Array.from([0]))
  let total = 0
  for (const p of parts) total += p.length
  const out = new Uint8Array(total)
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return toHex(out)
}

function rng(seed: number) {
  let s = seed >>> 0
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0
    return s
  }
}

describe('NameCoder fuzz (namehash on raw bytes)', () => {
  it('namehash matches reference for random byte-labels', async () => {
    const F = await loadFixture()
    const next = rng(0xC0FFEE)
    let checked = 0
    for (let iter = 0; iter < 400; iter++) {
      const nLabels = next() % 5 // 0..4 labels
      const labels: Uint8Array[] = []
      for (let j = 0; j < nLabels; j++) {
        const len = 1 + (next() % 6) // 1..6 bytes
        const l = new Uint8Array(len)
        for (let k = 0; k < len; k++) {
          let b = next() % 256
          if (b === 0x2e) b = 0x2d // avoid '.' (dot) inside a label
          if (b === 0x00) b = 0x01 // avoid embedded null
          l[k] = b
        }
        labels.push(l)
      }
      const dns = dnsEncode(labels)
      const got = await F.read.namehash([dns, 0n])
      const exp = refNamehash(labels)
      if (got !== exp) {
        throw new Error(
          `MISMATCH labels=${JSON.stringify(labels.map((x) => toHex(x)))} dns=${dns} got=${got} exp=${exp}`,
        )
      }
      // countLabels must agree
      const count = await F.read.countLabels([dns, 0n])
      if (count !== BigInt(nLabels)) {
        throw new Error(`COUNT MISMATCH dns=${dns} got=${count} exp=${nLabels}`)
      }
      checked++
    }
    expect(checked).toBe(400)
  })

  it('namehash matches reference for max-length labels', async () => {
    const F = await loadFixture()
    for (const len of [1, 2, 63, 64, 127, 255]) {
      const l = new Uint8Array(len).fill(0x61) // "aaaa..."
      const labels = [l]
      const dns = dnsEncode(labels)
      const got = await F.read.namehash([dns, 0n])
      const exp = refNamehash(labels)
      expect(got, `len=${len}`).toStrictEqual(exp)
    }
  })
})
