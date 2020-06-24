export type base64 = string;

import { sodium } from "./Crypto";

export function randomBytes(length: number): Uint8Array {
  return sodium.randombytes_buf(length);
}

export function toBase64(input: string | Uint8Array): string {
  return sodium.to_base64(input);
}

export function fromBase64(input: string): Uint8Array {
  return sodium.from_base64(input);
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
