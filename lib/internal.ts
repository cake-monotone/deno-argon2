import { HashOptions, MIN_SALT_SIZE } from "./common.ts";
import { Argon2Error, Argon2ErrorType } from "./error.ts";

const lib = await Deno.dlopen("./target/release/libdeno_argon2.so", {
  hash: {
    parameters: ["buffer", "usize"],
    result: "pointer",
    nonblocking: true,
  },
  verify: {
    parameters: ["buffer", "usize"],
    result: "pointer",
    nonblocking: true,
  },
});

function encode(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function decode(buf: Uint8Array): string {
  return new TextDecoder().decode(buf);
}

function readBuffer(v: Deno.PointerValue): Uint8Array {
  const ptr = new Deno.UnsafePointerView(v);
  const len = new DataView(ptr.getArrayBuffer(4)).getUint32(0);
  return new Uint8Array(ptr.getArrayBuffer(len, 4));
}

export async function hash(
  password: string,
  options: Partial<HashOptions> = {},
) {
  if (typeof password !== "string") {
    throw new Argon2Error(
      Argon2ErrorType.InvalidInput,
      "Password argument must be a string.",
    );
  }

  const salt = options.salt ? options.salt : crypto.getRandomValues(
    new Uint8Array(
      Math.max(Math.round(Math.random() * 32), MIN_SALT_SIZE),
    ),
  );

  if (salt.length < MIN_SALT_SIZE) {
    throw new Argon2Error(
      Argon2ErrorType.InvalidInput,
      `Input salt is too short: ${salt.length}`,
    );
  }

  const args = encode(JSON.stringify({
    password,
    options: {
      ...options,
      salt: [...salt.values()],
      secret: options.secret ? [...options.secret.values()] : undefined,
      data: options.data
        ? [...encode(JSON.stringify(options.data)).values()]
        : undefined,
    },
  }));

  const result = await lib.symbols.hash(
    args,
    args.byteLength,
  ).then(
    (r) =>
      JSON.parse(decode(readBuffer(r))) as {
        result: Array<number>;
        error: string | null;
      },
  );

  if (result.error) {
    throw new Argon2Error(
      Argon2ErrorType.Native,
      "An error occurred executing `hash`",
      result.error,
    );
  }

  return decode(Uint8Array.from(result.result));
}

export async function verify(
  hash: string,
  password: string,
) {
  const args = encode(JSON.stringify({
    hash: hash,
    password: password,
  }));
  const result = await lib.symbols.verify(
    args,
    args.byteLength,
  ).then(
    (r) =>
      JSON.parse(decode(readBuffer(r))) as {
        result: boolean;
        error: string | null;
      },
  );

  if (result.error) {
    throw new Argon2Error(
      Argon2ErrorType.Native,
      "An error occurred executing `verify`",
      result.error,
    );
  }

  return result.result;
}
