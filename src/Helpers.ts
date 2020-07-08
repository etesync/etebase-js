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

export function getPadding(length: number): number {
  // Use the padme padding scheme for efficiently
  // https://www.petsymposium.org/2019/files/papers/issue4/popets-2019-0056.pdf

  // We have a minimum padding of 32 (padme(512) == 32)
  const minPad = 512;
  if (length < minPad) {
    return 32;
  }

  const e = Math.floor(Math.log2(length));
  const s = Math.floor(Math.log2(e)) + 1;
  const lastBits = e - s;
  const bitMask = Math.pow(2, lastBits) - 1;
  return (length + bitMask) & ~bitMask;
}

export function bufferPad(buf: Uint8Array): Uint8Array {
  return sodium.pad(buf, getPadding(buf.length));
}

export function bufferUnpad(buf: Uint8Array): Uint8Array {
  if (buf.length === 0) {
    return buf;
  }

  // We pass the buffer's length as the block size because due to padme there's always some variable-sized padding.
  return sodium.unpad(buf, buf.length);
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

export function numFromUint8Array(buf: Uint8Array): number {
  if (buf.length !== 4) {
    throw new Error("numFromUint8Array: buffer should be of length 4.");
  }

  return (
    buf[0] +
    (buf[1] << 8) +
    (buf[2] << 16) +
    (((buf[3] << 23) >>> 0) * 2)
  );
}
