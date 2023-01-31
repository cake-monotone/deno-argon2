import { HashOptions, MIN_SALT_SIZE } from "./common.ts";
import { Argon2Error, Argon2ErrorType } from "./error.ts";
import * as argon2 from "../bindings/bindings.ts";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

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

  let salt = options.salt ? options.salt : crypto.getRandomValues(
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

  const result = await argon2.hash(
    password,
    {
      salt: [...salt.values()],
      secret: options.secret ? [...options.secret.values()] : undefined,
      data: options.data
        ? [...encoder.encode(JSON.stringify(options.data)).values()]
        : undefined,
      version: options.version,
      variant: options.variant,
      memory_cost: options.memoryCost,
      time_cost: options.timeCost,
      lanes: options.lanes,
      thread_mode: options.threadMode,
      hash_length: options.hashLength,
    },
  )

  if (result.error) {
    throw new Argon2Error(
      Argon2ErrorType.Native,
      "An error occurred executing `hash`",
      result.error,
    );
  }

  return decoder.decode(Uint8Array.from(result.result));
}

export async function verify(
  hash: string,
  password: string,
) {
  const result = await argon2.verify(hash, password)

  if (result.error) {
    throw new Argon2Error(
      Argon2ErrorType.Native,
      "An error occurred executing `verify`",
      result.error,
    );
  }

  return result.result;
}
