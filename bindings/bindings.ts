// Auto-generated with deno_bindgen
import { CachePolicy, prepare } from "https://deno.land/x/plug@0.5.2/plug.ts"

function encode(v: string | Uint8Array): Uint8Array {
  if (typeof v !== "string") return v
  return new TextEncoder().encode(v)
}

function decode(v: Uint8Array): string {
  return new TextDecoder().decode(v)
}

function readPointer(v: any): Uint8Array {
  const ptr = new Deno.UnsafePointerView(v as bigint)
  const lengthBe = new Uint8Array(4)
  const view = new DataView(lengthBe.buffer)
  ptr.copyInto(lengthBe, 0)
  const buf = new Uint8Array(view.getUint32(0))
  ptr.copyInto(buf, 4)
  return buf
}

const url = new URL("../target/release", import.meta.url)
let uri = url.toString()
if (!uri.endsWith("/")) uri += "/"

let darwin: string | { aarch64: string; x86_64: string } = uri
  + "libdeno_argon2.dylib"

if (url.protocol !== "file:") {
  // Assume that remote assets follow naming scheme
  // for each macOS artifact.
  darwin = {
    aarch64: uri + "libdeno_argon2_arm64.dylib",
    x86_64: uri + "libdeno_argon2.dylib",
  }
}

const opts = {
  name: "deno_argon2",
  urls: {
    darwin,
    windows: uri + "deno_argon2.dll",
    linux: uri + "libdeno_argon2.so",
  },
  policy: undefined,
}
const _lib = await prepare(opts, {
  hash: {
    parameters: ["pointer", "usize", "pointer", "usize"],
    result: "pointer",
    nonblocking: true,
  },
  verify: {
    parameters: ["pointer", "usize", "pointer", "usize"],
    result: "pointer",
    nonblocking: true,
  },
})
export type HashOptions = {
  salt: Array<number>
  secret: Array<number> | undefined | null
  data: Array<number> | undefined | null
  version: string | undefined | null
  variant: string | undefined | null
  memory_cost: number | undefined | null
  time_cost: number | undefined | null
  lanes: number | undefined | null
  thread_mode: number | undefined | null
  hash_length: number | undefined | null
}
export type HashResult = {
  result: Array<number>
  error: string | undefined | null
}
export type VerifyResult = {
  result: boolean
  error: string | undefined | null
}
export function hash(a0: string, a1: HashOptions) {
  const a0_buf = encode(a0)
  const a1_buf = encode(JSON.stringify(a1))
  const a0_ptr = Deno.UnsafePointer.of(a0_buf)
  const a1_ptr = Deno.UnsafePointer.of(a1_buf)
  let rawResult = _lib.symbols.hash(
    a0_ptr,
    a0_buf.byteLength,
    a1_ptr,
    a1_buf.byteLength,
  )
  const result = rawResult.then(readPointer)
  return result.then(r => JSON.parse(decode(r))) as Promise<HashResult>
}
export function verify(a0: string, a1: string) {
  const a0_buf = encode(a0)
  const a1_buf = encode(a1)
  const a0_ptr = Deno.UnsafePointer.of(a0_buf)
  const a1_ptr = Deno.UnsafePointer.of(a1_buf)
  let rawResult = _lib.symbols.verify(
    a0_ptr,
    a0_buf.byteLength,
    a1_ptr,
    a1_buf.byteLength,
  )
  const result = rawResult.then(readPointer)
  return result.then(r => JSON.parse(decode(r))) as Promise<VerifyResult>
}
