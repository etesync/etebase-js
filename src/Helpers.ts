import * as msgpack from "@msgpack/msgpack";

import { sodium } from "./Crypto";

export type base64 = string;

export const symmetricKeyLength = 32; // sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
export const symmetricTagLength = 16; // sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES;
export const symmetricNonceSize = 24; // sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

export function randomBytes(length: number): Uint8Array {
  return sodium.randombytes_buf(length);
}

export function toBase64(input: string | Uint8Array): string {
  return sodium.to_base64(input);
}

export function fromBase64(input: string): Uint8Array {
  return sodium.from_base64(input);
}

export function toString(input: Uint8Array): string {
  return sodium.to_string(input);
}

export function fromString(input: string): Uint8Array {
  return sodium.from_string(input);
}

export function memcmp(b1: Uint8Array, b2: Uint8Array): boolean {
  return sodium.memcmp(b1, b2);
}

export function msgpackEncode(value: unknown): Uint8Array {
  const options = { ignoreUndefined: true };
  return msgpack.encode(value, options);
}

export function msgpackDecode(buffer: ArrayLike<number> | ArrayBuffer): unknown {
  return msgpack.decode(buffer);
}

export function numToUint8Array(num: number): Uint8Array {
  // We are using little-endian because on most platforms it'll mean zero-conversion
  return Uint8Array.from([
    num & 255,
    (num >> 8) & 255,
    (num >> 16) & 255,
    (num >> 24) & 255,
  ]);
}
