import * as msgpack from "@msgpack/msgpack";

import _sodium from "libsodium-wrappers";

const sodium = _sodium;

export type base64 = string;

export const symmetricKeyLength = 32; // sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
export const symmetricTagLength = 16; // sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES;
export const symmetricNonceSize = 24; // sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

export function randomBytes(length: number): Uint8Array {
  return sodium.randombytes_buf(length);
}

export function randomBytesDeterministic(length: number, seed: Uint8Array): Uint8Array {
  return sodium.randombytes_buf_deterministic(length, seed);
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

// Fisher–Yates shuffle - an unbiased shuffler
// The returend indices of where item is now.
// So if the first item moved to position 3: ret[0] = 3
export function shuffle<T>(a: T[]): number[] {
  const len = a.length;
  const shuffledIndices = new Array(len);

  // Fill up with the indices
  for (let i = 0 ; i < len ; i++) {
    shuffledIndices[i] = i;
  }

  for (let i = 0 ; i < len ; i++) {
    const j = i + sodium.randombytes_uniform(len - i);
    const tmp = a[i];
    a[i] = a[j];
    a[j] = tmp;

    // Also swap the index array
    const tmp2 = shuffledIndices[i];
    shuffledIndices[i] = shuffledIndices[j];
    shuffledIndices[j] = tmp2;
  }

  const ret = new Array(len);
  for (let i = 0 ; i < len ; i++) {
    ret[shuffledIndices[i]] = i;
  }

  return ret;
}

export function getPadding(length: number): number {
  // Use the padme padding scheme for efficiently
  // https://www.petsymposium.org/2019/files/papers/issue4/popets-2019-0056.pdf

  // We want a minimum pad size of 4k
  if (length < (1 << 14)) {
    const size = (1 << 10) - 1;
    // We add 1 so we always have some padding
    return (length | size) + 1;
  }

  const e = Math.floor(Math.log2(length));
  const s = Math.floor(Math.log2(e)) + 1;
  const lastBits = e - s;
  const bitMask = Math.pow(2, lastBits) - 1;
  return (length + bitMask) & ~bitMask;
}

// FIXME: we should properly pad the meta and probably change these functions
// This function is the same as bufferPad, but doesn't enforce a large minimum padding size
export function bufferPadSmall(buf: Uint8Array): Uint8Array {
  return sodium.pad(buf, buf.length + 1);
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

export function bufferPadFixed(buf: Uint8Array, blocksize: number): Uint8Array {
  return sodium.pad(buf, blocksize);
}

export function bufferUnpadFixed(buf: Uint8Array, blocksize: number): Uint8Array {
  return sodium.unpad(buf, blocksize);
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
  return new Uint8Array([
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
