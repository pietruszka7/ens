import hre from 'hardhat'
import { toHex, bytesToHex } from 'viem'

const connection = await hre.network.connect()

async function fixture() {
  const ensip19 = await connection.viem.deployContract('TestENSIP19', [])
  const namecoder = await connection.viem.deployContract('TestNameCoder', [])
  return { ensip19, namecoder }
}
const loadFixture = async () => connection.networkHelpers.loadFixture(fixture)

function rng(seed: number) {
  let s = seed >>> 0
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0
    return s
  }
}

const COIN_TYPE_ETH = 60n
const COIN_TYPE_DEFAULT = 1n << 31n

describe('ENSIP19 reverseName <-> parse round-trip', () => {
  it('round-trips random addr + coinType', async () => {
    const F = await loadFixture()
    const next = rng(0x1234abcd)
    let checked = 0
    const coinTypes: bigint[] = [
      COIN_TYPE_ETH,
      COIN_TYPE_DEFAULT,
      COIN_TYPE_DEFAULT | 10n, // EVM chain 10 (optimism)
      COIN_TYPE_DEFAULT | 8453n, // base
      COIN_TYPE_DEFAULT | 1n,
      0n, // bitcoin-ish / non-evm
      2n,
      0x80000000n + 0x7fffffffn, // edge
    ]
    for (let iter = 0; iter < 200; iter++) {
      // random 20-byte address
      const addr = new Uint8Array(20)
      for (let k = 0; k < 20; k++) addr[k] = next() % 256
      const ct = coinTypes[next() % coinTypes.length]

      const name: string = await F.ensip19.read.reverseName([
        bytesToHex(addr),
        ct,
      ])
      const dns = await F.namecoder.read.encode([name])
      const [gotAddr, gotCt] = await F.ensip19.read.parse([dns])

      if (gotAddr.toLowerCase() !== bytesToHex(addr).toLowerCase()) {
        throw new Error(
          `ADDR MISMATCH name="${name}" ct=${ct} got=${gotAddr} exp=${bytesToHex(addr)}`,
        )
      }
      if (gotCt !== ct) {
        throw new Error(
          `COINTYPE MISMATCH name="${name}" exp=${ct} got=${gotCt} (addr=${bytesToHex(addr)})`,
        )
      }
      checked++
    }
    expect(checked).toBe(200)
  })
})

describe('NameCoder encode <-> decode bijectivity', () => {
  it('decode(encode(name)) == name for random byte-labels', async () => {
    const F = await loadFixture()
    const next = rng(0xfeed5)
    let checked = 0
    for (let iter = 0; iter < 300; iter++) {
      const nLabels = 1 + (next() % 4)
      const labels: string[] = []
      for (let j = 0; j < nLabels; j++) {
        const len = 1 + (next() % 8)
        const bytesArr = new Uint8Array(len)
        for (let k = 0; k < len; k++) {
          let b = 0x21 + (next() % (0x7e - 0x21)) // printable ASCII excluding space
          if (b === 0x2e) b = 0x2d // no dot inside label
          bytesArr[k] = b
        }
        labels.push(Buffer.from(bytesArr).toString('latin1'))
      }
      const name = labels.join('.')
      const dns = await F.namecoder.read.encode([name])
      const back = await F.namecoder.read.decode([dns])
      if (back !== name) {
        throw new Error(
          `BIJECTION FAIL name="${name}" dns=${dns} decoded="${back}"`,
        )
      }
      checked++
    }
    expect(checked).toBe(300)
  })
})
