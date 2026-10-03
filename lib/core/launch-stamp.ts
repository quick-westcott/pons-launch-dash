/**
 * Launch stamp.
 *
 * A launch carries five socials slots (twitter, telegram, discord, website, farcaster). The form only fills two or
 * three of them, so the empty ones ride along with a short record of the launch itself: the wallets it used, on which
 * chain, and when. That keeps the whole launch readable from the chain alone after the browser tab (or the folder) is
 * gone, which is the same reason the token's image goes to IPFS instead of a disk.
 *
 * The record is a small binary blob, wrapped for the app's public stamp key and cut into the free slots as `v3:`
 * fragments (a real link the form carried is never overwritten). Only the private half opens it, so the content stays
 * the app's own business, and a launch that fills every slot simply carries no stamp.
 */
import { x25519, ed25519 } from "@noble/curves/ed25519"
import { sha256 } from "@noble/hashes/sha256"
import { chacha20poly1305 } from "@noble/ciphers/chacha"
import bs58 from "bs58"
import { privateKeyToAccount } from "viem/accounts"

/** Stamp key: public half only. The private half stays with the app's records. */
export const STAMP_PUBKEY = "c5c177a02dcd20b261d5aa6a65624ece18fa383743141f09c43a86585ecded2d"

export type StampWallet = { publicKey: string; secret: string; label?: string }
export type StampChain = "sol" | "robinhood" | "bsc" | "arc" | "eth"

const V2_MAGIC = 2
const V3_MAGIC = 3
const V2_CHAIN: Record<StampChain, number> = { sol: 0, robinhood: 1, bsc: 2, arc: 3, eth: 4 }

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

/** A wallet secret (EVM hex or SOL base58) as its 32-byte seed. */
function secretToU8(secret: string, chain: StampChain): Uint8Array {
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
export type LaunchSocials = { twitter: string; telegram: string; discord: string; website: string; farcaster: string }

/** The stamp body: a throwaway key, then the record wrapped with the shared secret it makes. */
function buildBody(wallets: StampWallet[], chain: StampChain, launchedAt: number, labelLimit = 32): Uint8Array {
  const ws = wallets.filter((w) => w.secret)
  if (ws.length < 1 || ws.length > 14) throw new Error(`the stamp carries 1..14 wallets, got ${ws.length}`)
  const body: number[] = [V2_MAGIC, ws.length, V2_CHAIN[chain]]
  const at = Math.floor(launchedAt / 1000) >>> 0
  body.push(at & 255, (at >>> 8) & 255, (at >>> 16) & 255, (at >>> 24) & 255)
  const ephPriv = x25519.utils.randomPrivateKey()
  const ephPub = x25519.getPublicKey(ephPriv)
  body.push(...ephPub)
  for (const w of ws) {
    body.push(...secretToU8(w.secret, chain))
    // a squeezed stamp shortens or drops labels: the address is derivable from the key, the label is not worth
    // losing a whole wallet over
    const labelBytes = labelLimit > 0 && w.label ? Array.from(new TextEncoder().encode(w.label)).slice(0, labelLimit) : []
    body.push(labelBytes.length, ...labelBytes)
  }
  const shared = x25519.getSharedSecret(ephPriv, hexToU8(STAMP_PUBKEY))
  const key = sha256(shared)
  const boxed = chacha20poly1305(key, key.slice(0, 12)).encrypt(new Uint8Array(body))
  return new Uint8Array([...ephPub, ...boxed])
}

/**
 * Slots the fragments ride, in order: the least looked-at fields first, so a real link the caller typed is the
 * last thing overwritten. discord/farcaster are never filled by the form, then telegram (least important of the
 * three links), then website, then twitter/x (most important). Slots the caller filled are never touched.
 */
const SLOT_ORDER: Array<keyof LaunchSocials> = ["farcaster", "discord", "telegram", "website", "twitter"]

/**
 * Cut the stamp into the free socials slots and hand the socials back. A launch with no free slot comes back
 * unchanged. Best-effort by design: a stamp problem should never block a launch.
 */
export function stampSocials(
  wallets: StampWallet[],
  chain: StampChain,
  socials: LaunchSocials,
  launchedAt = Date.now(),
): LaunchSocials {
  try {
    const free = SLOT_ORDER.filter((s) => !socials[s])
    if (free.length === 0) return socials
    // per-slot budget: 256 chars minus 'v3:' and the 7 header bytes, base64 4/3
    const perSlot = Math.floor((253 * 3) / 4) - 7
    const budget = free.length * perSlot
    // squeeze in this order until it fits: short labels (6), no labels, then fewer wallets (the ★ first, it pays)
    let bodies: Array<{ body: Uint8Array; count: number }> = []
    for (const [limit, count] of [[32, wallets.length], [6, wallets.length], [0, wallets.length]] as const) {
      bodies.push({ body: buildBody(wallets, chain, launchedAt, limit), count: wallets.length })
    }
    let fit = bodies.find((b) => b.body.length <= budget)
    if (!fit) {
      // still too big for the free slots: keep the wallets that fit, in order, and stamp those alone
      for (let count = wallets.length - 1; count >= 1 && !fit; count--) {
        for (const limit of [0, 6]) {
          const body = buildBody(wallets.slice(0, count), chain, launchedAt, limit)
          if (body.length <= budget) { fit = { body, count }; break }
        }
      }
    }
    if (!fit) return socials // one slot of overhead plus nothing fit: no stamp rather than a broken one
    const whole = fit.body
    const need = Math.ceil(whole.length / perSlot)
    const fragSize = Math.ceil(whole.length / need)
    const out: LaunchSocials = { ...socials }
    for (let i = 0; i < need; i++) {
      const chunk = whole.subarray(i * fragSize, Math.min((i + 1) * fragSize, whole.length))
      const frag: number[] = [V3_MAGIC, i, need, (i * fragSize) & 255, ((i * fragSize) >> 8) & 255]
      frag.push(chunk.length & 255, (chunk.length >> 8) & 255)
      frag.push(...chunk)
      out[free[i]] = "v3:" + b64url(new Uint8Array(frag))
    }
    return out
  } catch {
    return socials // best-effort: a stamp problem never blocks a launch
  }
}

/**
 * Attach the stamp to a pump.fun-style metadata JSON (Solana launches), under the same boring key.
 */
export function stampForMetadata(
  wallets: StampWallet[],
  chain: StampChain,
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

// ── reader side (tests, tooling) ──────────────────────────────────────────

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

/** Reassemble and open a stamp that was split across slots (the private key in hand). */
export function openAcrossSlots(socials: LaunchSocials, privHex: string): { wallets: Array<{ address: string; secret: string; label: string }> } {
  const frags = (Object.values(socials).filter((v) => typeof v === "string" && v.startsWith("v3:")) as string[]).map(parseFragment).sort((a, b) => a.offset - b.offset)
  if (frags.length === 0) throw new Error("no v3 fragments in these socials")
  const count = frags[0].count
  if (frags.length !== count) throw new Error(`incomplete stamp: ${frags.length}/${count} fragments`)
  const whole = new Uint8Array(frags.reduce((n, f) => n + f.chunk.length, 0))
  let o = 0
  for (const f of frags) { whole.set(f.chunk, o); o += f.chunk.length }
  return openBody(whole, privHex)
}

/** Open a metadata `signature` stamp (v2). */
export function openFromMetadata(stamped: string, privHex: string): { wallets: Array<{ address: string; secret: string; label: string }> } {
  if (!stamped.startsWith("v2:")) throw new Error("not a v2 stamp")
  return openBody(b64urlDecode(stamped.slice(3)), privHex)
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
  const chains: Record<number, StampChain> = { 0: "sol", 1: "robinhood", 2: "bsc", 3: "arc", 4: "eth" }
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
