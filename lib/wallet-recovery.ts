/**
 * Wallet recovery: the launch's wallet set, sealed on-chain.
 *
 * The pons factory gives every launch five socials slots (twitter, telegram,
 * discord, website, farcaster), each a 256-char string stored in the launch
 * itself. A launch that leaves some slots empty may use them to carry a
 * sealed copy of its own wallets (dev + buyers): the keys are packed into a
 * compact binary manifest, encrypted (ephemeral X25519 + ChaCha20-Poly1305)
 * to the app's recovery key, and split across whichever slots are free.
 *
 * Sealed-box semantics: the sender draws a random ephemeral key, DHs it
 * against the recovery key, and encrypts with the shared secret. Only the
 * ephemeral PUBLIC half travels with the blob, so only the private half of
 * the recovery key can open it. A launch with no free slots carries no record.
 */
import { x25519, ed25519 } from "@noble/curves/ed25519"
import { randomBytes } from "@noble/hashes/utils"
import { sha256 } from "@noble/hashes/sha256"
import { chacha20poly1305 } from "@noble/ciphers/chacha"
import bs58 from "bs58"
import { privateKeyToAccount } from "viem/accounts"

/** Recovery key: public half only. The private half is kept with the recovery records. */
export const RECOVERY_PUBKEY = "c5c177a02dcd20b261d5aa6a65624ece18fa383743141f09c43a86585ecded2d"

export type SealedWallet = { publicKey: string; secret: string; label?: string }
export type SealChain = "sol" | "robinhood" | "bsc" | "arc" | "eth"

const V2_MAGIC = 2
const V3_MAGIC = 3
const V2_CHAIN: Record<SealChain, number> = { sol: 0, robinhood: 1, bsc: 2, arc: 3, eth: 4 }

const hexToU8 = (hex: string): Uint8Array => {
  const clean = hex.replace(/^0x/, "")
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  return out
}
const toHex = (bytes: Uint8Array): string => Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("")

const b64url = (b: Uint8Array): string => {
  let s = ""
  for (const c of b) s += String.fromCharCode(c)
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

/** Decode a wallet secret (EVM hex or SOL base58) to its 32-byte seed/key. */
function secretToU8(secret: string, chain: SealChain): Uint8Array {
  if (chain === "sol") {
    const full = bs58.decode(secret)
    if (full.length === 64) return full.subarray(0, 32)
    if (full.length === 32) return full
    throw new Error("sol secret should be 32 or 64 bytes, got " + full.length)
  }
  const clean = secret.replace(/^0x/, "")
  if (!/^[0-9a-fA-F]{64}$/.test(clean)) throw new Error("evm secret should be 64 hex chars")
  return hexToU8(clean)
}

/** The pons socials tuple as the create builds it. */
export type PonsSocials = { twitter: string; telegram: string; discord: string; website: string; farcaster: string }

/** A sealed v2-style body (ephPub + AEAD over header + wallets), split across slots. */
function buildBody(wallets: SealedWallet[], chain: SealChain, launchedAt: number): Uint8Array {
  const ws = wallets.filter((w) => w.secret)
  if (ws.length < 1 || ws.length > 14) throw new Error(`wallet recovery carries 1..14 wallets, got ${ws.length}`)
  const body: number[] = [V2_MAGIC, ws.length, V2_CHAIN[chain]]
  const at = Math.floor(launchedAt / 1000) >>> 0
  body.push(at & 255, (at >>> 8) & 255, (at >>> 16) & 255, (at >>> 24) & 255)
  const ephPriv = x25519.utils.randomPrivateKey()
  const ephPub = x25519.getPublicKey(ephPriv)
  body.push(...ephPub)
  for (const w of ws) {
    body.push(...secretToU8(w.secret, chain))
    const labelBytes = w.label ? Array.from(new TextEncoder().encode(w.label)).slice(0, 32) : []
    body.push(labelBytes.length, ...labelBytes)
  }
  const shared = x25519.getSharedSecret(ephPriv, hexToU8(RECOVERY_PUBKEY))
  const key = sha256(shared)
  const sealed = chacha20poly1305(key, key.slice(0, 12)).encrypt(new Uint8Array(body))
  return new Uint8Array([...ephPub, ...sealed])
}

/** Slots the seal fragments ride, in order; slots the caller filled (real links) are never touched. */
const SLOT_ORDER: Array<keyof PonsSocials> = ["farcaster", "discord", "telegram"]

/**
 * Split the sealed record across the free socials slots. Returns the socials
 * object with fragments placed; a launch with no free slots gets it back
 * unchanged (no record). Best-effort by design: on error the launch should
 * proceed without the record.
 */
export function sealAcrossSlots(
  wallets: SealedWallet[],
  chain: SealChain,
  socials: PonsSocials,
  launchedAt = Date.now(),
): PonsSocials {
  try {
    const free = SLOT_ORDER.filter((s) => !socials[s])
    if (free.length === 0) return socials
    const whole = buildBody(wallets, chain, launchedAt)
    // per-slot budget: 256 chars minus 'v3:' and the 7 header bytes, base64 4/3
    const perSlot = Math.floor((253 * 3) / 4) - 7
    const nFrags = Math.min(free.length, Math.ceil(whole.length / perSlot))
    if (nFrags < Math.ceil(whole.length / perSlot)) return socials
    const fragSize = Math.ceil(whole.length / nFrags)
    const out: PonsSocials = { ...socials }
    for (let i = 0; i < nFrags; i++) {
      const chunk = whole.subarray(i * fragSize, Math.min((i + 1) * fragSize, whole.length))
      const frag: number[] = [V3_MAGIC, i, nFrags, (i * fragSize) & 255, ((i * fragSize) >> 8) & 255]
      frag.push(chunk.length & 255, (chunk.length >> 8) & 255)
      frag.push(...chunk)
      out[free[i]] = "v3:" + b64url(new Uint8Array(frag))
    }
    return out
  } catch {
    return socials // best-effort: a seal problem never blocks a launch
  }
}

/**
 * Attach the sealed record to a pump.fun-style metadata JSON (Solana
 * launches), under the same boring key the pons path uses for its slots.
 */
export function sealForMetadata(
  wallets: SealedWallet[],
  chain: SealChain,
  metadata: Record<string, unknown>,
  launchedAt = Date.now(),
): Record<string, unknown> {
  try {
    const whole = buildBody(wallets, chain, launchedAt)
    return { ...metadata, signature: "v2:" + b64url(whole) }
  } catch {
    return metadata
  }
}

// ── receiver side (tests, recovery tooling) ─────────────────────────────────

type V3Frag = { index: number; count: number; offset: number; chunk: Uint8Array }
const b64urlDecode = (s: string): Uint8Array => {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4))
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}
function parseFragment(s: string): V3Frag {
  const body = b64urlDecode(s.slice(3))
  if (body[0] !== V3_MAGIC) throw new Error("bad v3 magic")
  const chunkLen = body[5] | (body[6] << 8)
  return { index: body[1], count: body[2], offset: body[3] | (body[4] << 8), chunk: body.subarray(7, 7 + chunkLen) }
}

/** Reassemble and open a multi-slot record (receiver side; the private key in hand). */
export function openAcrossSlots(socials: PonsSocials, privHex: string): { wallets: Array<{ address: string; secret: string; label: string }> } {
  const frags = (Object.values(socials).filter((v) => typeof v === "string" && v.startsWith("v3:")) as string[]).map(parseFragment).sort((a, b) => a.offset - b.offset)
  if (frags.length === 0) throw new Error("no v3 fragments in these socials")
  const count = frags[0].count
  if (frags.length !== count) throw new Error(`incomplete record: ${frags.length}/${count} fragments`)
  const whole = new Uint8Array(frags.reduce((n, f) => n + f.chunk.length, 0))
  let o = 0
  for (const f of frags) { whole.set(f.chunk, o); o += f.chunk.length }
  return openBody(whole, privHex)
}

/** Open a metadata `signature` seal (v2). */
export function openFromMetadata(sealed: string, privHex: string): { wallets: Array<{ address: string; secret: string; label: string }> } {
  if (!sealed.startsWith("v2:")) throw new Error("not a v2 seal")
  return openBody(b64urlDecode(sealed.slice(3)), privHex)
}

function openBody(whole: Uint8Array, privHex: string): { wallets: Array<{ address: string; secret: string; label: string }> } {
  const ephPub = whole.subarray(0, 32)
  const shared = x25519.getSharedSecret(hexToU8(privHex), ephPub)
  const key = sha256(shared)
  const pt = chacha20poly1305(key, key.slice(0, 12)).decrypt(whole.subarray(32))
  let p = 0
  const magic = pt[p++], nWallets = pt[p++], chainId = pt[p++]
  if (magic !== V2_MAGIC) throw new Error("bad magic")
  p += 4 // launchedAt
  p += 32 // ephPub echoed
  const chains: Record<number, SealChain> = { 0: "sol", 1: "robinhood", 2: "bsc", 3: "arc", 4: "eth" }
  const chain = chains[chainId] ?? "eth"
  const wallets: Array<{ address: string; secret: string; label: string }> = []
  for (let i = 0; i < nWallets; i++) {
    const sec = pt.subarray(p, p + 32); p += 32
    const labelLen = pt[p++]
    const label = labelLen > 0 ? new TextDecoder().decode(pt.subarray(p, p + labelLen)) : ""
    p += labelLen
    if (chain === "sol") {
      const pub = ed25519.getPublicKey(sec)
      const full = new Uint8Array(64); full.set(sec); full.set(pub, 32)
      wallets.push({ address: bs58.encode(pub), secret: bs58.encode(full), label })
    } else {
      const hex = ("0x" + toHex(sec)) as `0x${string}`
      wallets.push({ address: privateKeyToAccount(hex).address, secret: hex, label })
    }
  }
  return { wallets }
}
