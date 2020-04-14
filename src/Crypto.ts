import _sodium from 'libsodium-wrappers';

import * as Constants from './Constants';

export const sodium = _sodium;
export const ready = _sodium.ready;

export function concatArrayBuffers(buffer1: Uint8Array, buffer2: Uint8Array): Uint8Array {
  const ret = new Uint8Array(buffer1.length + buffer2.length);
  ret.set(buffer1, 0);
  ret.set(buffer2, buffer1.length);
  return ret;
}

export function deriveKey(salt: Uint8Array, password: string): Uint8Array {
  // XXX should probably move to scrypt or at least change parameters. - we need it fast in JS most likely

  return sodium.crypto_pwhash(
    32,
    Buffer.from(password),
    salt,
    sodium.crypto_pwhash_OPSLIMIT_MODERATE,
    sodium.crypto_pwhash_MEMLIMIT_MODERATE,
    sodium.crypto_pwhash_ALG_DEFAULT
  );
}

export class CryptoManager {
  protected version: number;
  protected cipherKey: Uint8Array;
  protected macKey: Uint8Array;

  constructor(key: Uint8Array, keyContext: string, version: number = Constants.CURRENT_VERSION) {
    this.version = version;

    this.cipherKey = sodium.crypto_kdf_derive_from_key(32, 1, keyContext, key);
    this.macKey = sodium.crypto_kdf_derive_from_key(32, 2, keyContext, key);
  }

  public encrypt(message: Uint8Array, additionalData: Uint8Array | null = null): Uint8Array {
    const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    return concatArrayBuffers(nonce,
      sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(message, additionalData, null, nonce, this.cipherKey));
  }

  public decrypt(nonceCiphertext: Uint8Array, additionalData: Uint8Array | null = null): Uint8Array {
    const nonceSize = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    const nonce = nonceCiphertext.subarray(0, nonceSize);
    const ciphertext = nonceCiphertext.subarray(nonceSize);
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, additionalData, nonce, this.cipherKey);
  }

  public encryptDetached(message: Uint8Array, additionalData: Uint8Array | null = null): [Uint8Array, Uint8Array] {
    const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    const ret = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(message, additionalData, null, nonce, this.cipherKey);
    return [ret.mac, concatArrayBuffers(nonce, ret.ciphertext)];
  }

  public decryptDetached(nonceCiphertext: Uint8Array, mac: Uint8Array, additionalData: Uint8Array | null = null): Uint8Array {
    const nonceSize = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    const nonce = nonceCiphertext.subarray(0, nonceSize);
    const ciphertext = nonceCiphertext.subarray(nonceSize);
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt_detached(null, ciphertext, mac, additionalData, nonce, this.cipherKey);
  }

  public getCryptoMac() {
    return new CryptoMac(this.macKey);
  }
}

export class CryptoMac {
  private state: _sodium.StateAddress;
  private length: number;

  constructor(key: Uint8Array, length = 32) {
    this.length = length;
    this.state = sodium.crypto_generichash_init(key, length);
  }

  public update(messageChunk: Uint8Array) {
    sodium.crypto_generichash_update(this.state, messageChunk);
  }

  public finalize() {
    return sodium.crypto_generichash_final(this.state, this.length);
  }
}
