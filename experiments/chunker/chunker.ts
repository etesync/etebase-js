import fs from "fs";

import { sodium } from "../../src/Crypto";
import { numToUint8Array, numFromUint8Array, getPadding, toBase64 } from "../../src/Helpers";

/**
 * Buzhash implements cyclic polymomial rolling hash function.
 * It is a custom developed keyed variant with protections against plain text
 * recovery from chunk lengths.
 *
 * Reading:
 *
 * http://www.serve.net/buz/Notes.1st.year/HTML/C6/rand.012.html
 * http://www.serve.net/buz/hash.adt/java.002.html
 * https://en.wikipedia.org/wiki/Rolling_hash#Cyclic_polynomial
 *
 * Buzhash is used to split data into content-dependent chunks.
 *
 * To make it difficult to guess plain text by watching split points,
 * we apply the following measures using a secret key:
 *
 *  - Substitution table is pseudorandomly permuted.
 *  - Initial 32-bit state is derived from key.
 *  - Window size slightly varies depending on key.
 *
 * To further enhance protection, it's a good idea to pad chunks
 * before encrypting them to hide their original length.
 *
 * Some parts taken from: https://gist.github.com/dchest/50d52015939a5772497815dcd33a7983
 */
export class Buzhash {
  private _initialState: number;
  private _state: number;
  private _windowSize: number;

  private _table: Uint32Array;

  constructor(windowSize: number, seed: Uint8Array) {
    if (seed.length !== 32) {
      throw new Error("Buzhash: key must be 32 bytes");
    }

    // We reqire the seed to be 16 bytes internally
    seed = seed.subarray(0, 16);

    this._table = generateTable(seed);

    // Set the initial state to a pseudorandom value.
    this._initialState = scramble(seed, 0xFFFFFF01);

    // Pseudorandomly vary window size by ~1/4.
    const wmin = windowSize - Math.floor(windowSize / 4);
    const wmax = windowSize + Math.ceil(windowSize / 4);
    const rnd = scramble(seed, 0xFFFFFF02);
    windowSize = rnd % (wmax - wmin + 1) + wmin; // ignoring mod bias

    // XXX If we ever change this, we need to make sure to change the last line of update to:
    // this._state ^= rotr(this._table[removeChar], this._windowSize & 0x1f);
    // Make window size divisible by 32.
    windowSize = Math.ceil(windowSize / 32) * 32;

    this._windowSize = windowSize;

    this.reset();
  }

  reset(): this {
    this._state = this._initialState;
    return this;
  }

  /*
   * Start the process by going through the buf and taking the first windowSize chars.
   * Returns the position to start from after
   */
  start(buf: Uint8Array): number {
    const len = Math.min(buf.length, this._windowSize);
    for (let i = 0 ; i < len ; i++) {
      this._state = rotr(this._state, 1) ^ this._table[buf[i]];
    }

    return len;
  }

  update(buf: Uint8Array, pos: number) {
    const removeChar = buf[pos - this._windowSize];
    const addChar = buf[pos];

    this._state = rotr(this._state, 1) ^ this._table[addChar];
    // Remove the char from the start of the window:
    this._state ^= this._table[removeChar];
  }

  digest(): number {
    return this._state;
  }

  /**
   * Returns true if splitting is needed, that is when the current digest
   * reaches the given number of the same consecutive low bits.
   */
  split(mask: number): boolean {
    return (this.digest() & mask) === 0;
  }

  clean() {
    this._initialState = 0;
    this._windowSize = 0;
    this.reset();
    wipe(this._table);
  }
}

/**
 * Generates a 256-number table of pseudorandom 32-bit unsigned integers such
 * that every bit position in the table has exactly 128 zeros and 128 ones.
 */
function generateTable(seed: Uint8Array): Uint32Array {
  const bits = new Uint8Array(256);
  const table = new Uint32Array(256);
  let ctr = 1;

  // Fill bits table with alternating 0 and 1.
  for (let i = 0; i < 256; i++) {
    bits[i] = i & 1;
  }

  // Generate table.
  for (let i = 0; i < 32; i++) {
    // Permute bits table.
    let pi = 0;
    while (pi < 256) {
      // Generate 4 pseudorandom bytes.
      let rnd = scramble(seed, ctr++);
      // Take each pseudorandom byte as index
      // and swap bit table value at this index.
      for (let k = 0; k < 4; k++) {
        const pj = rnd & 0xff;
        const tmp = bits[pi];
        bits[pi] = bits[pj];
        bits[pj] = tmp;
        rnd >>= 8;
        pi++;
      }
    }
    // Set bit in each integer in the table
    // according to the value in bits table.
    for (let j = 0; j < 256; j++) {
      table[j] = (table[j] << 1) | bits[j];
    }
  }

  wipe(bits);
  return table;
}

function wipe(bytes: Uint8Array | Uint32Array) {
  if (bytes instanceof Uint8Array) {
    sodium.memzero(bytes);
  } else {
    bytes.fill(0);
  }
}

function scramble(key: Uint8Array, v: number): number {
  const hash = sodium.crypto_shorthash(numToUint8Array(v), key);
  return numFromUint8Array(hash.subarray(0, 4));
}

function rotr(v: number, shift: number): number {
  shift = shift & 0x1f; // mod 32
  return ((v << shift) | (v >>> (32 - shift))) >>> 0;
}

export class MovingSum {
  private _initialState: number;
  private _state: number;
  private _windowSize: number;

  constructor(_windowSize: number, seed: Uint8Array) {
    if (seed.length !== 32) {
      throw new Error("Buzhash: key must be 32 bytes");
    }

    // We reqire the seed to be 16 bytes internally
    seed = seed.subarray(0, 16);
    this._windowSize = 8196;
    this._initialState = scramble(seed, 0xFFFFFF01);

    this.reset();
  }

  reset(): this {
    this._state = this._initialState;
    return this;
  }

  /*
   * Start the process by going through the buf and taking the first windowSize chars.
   * Returns the position to start from after
   */
  start(buf: Uint8Array): number {
    const len = Math.min(buf.length, this._windowSize);
    for (let i = 0 ; i < len ; i++) {
      this._state += buf[i];
    }

    return len;
  }

  update(buf: Uint8Array, pos: number) {
    const removeChar = buf[pos - this._windowSize];
    const addChar = buf[pos];

    this._state = this._state + addChar - removeChar;
  }

  /**
   * Returns true if splitting is needed, that is when the current digest
   * reaches the given number of the same consecutive low bits.
   */
  split(mask: number): boolean {
    return (this._state & mask) === 0;
  }

  clean() {
    this._initialState = 0;
    this._windowSize = 0;
    this.reset();
  }
}

export class Rollsum {
  private s1: number;
  private s2: number;
  private window: Uint8Array;
  private wofs: number;

  private windowSize: number;
  private charOffset: number;

  constructor(_windowSize: number, seed: Uint8Array) {
    if (seed.length !== 32) {
      throw new Error("Buzhash: key must be 32 bytes");
    }

    this.windowSize = 64;
    this.charOffset = 31;

    this.window = new Uint8Array(this.windowSize);
    this.reset();
  }

  reset(): this {
    this.window.fill(0);
    this.s1 = this.windowSize * this.charOffset;
    this.s2 = this.windowSize * (this.windowSize - 1) * this.charOffset;
    this.wofs = 0;

    return this;
  }

  /*
   * Start the process by going through the buf and taking the first windowSize chars.
   * Returns the position to start from after
   */
  start(_buf: Uint8Array): number {
    return 0;
  }

  update(buf: Uint8Array, pos: number) {
    const ch = buf[pos];
    this.rollsumAdd(this.window[this.wofs], ch);
    this.window[this.wofs] = (ch);
    this.wofs = (this.wofs + 1) % this.windowSize;
  }

  private rollsumAdd(drop: number, add: number) {
    this.s1 = (this.s1 + add - drop) >>> 0;
    this.s2 = (this.s2 + this.s1 - (this.windowSize * (drop + this.charOffset))) >>> 0;
  }

  digest(): number {
    return ((this.s1 << 16) | (this.s2 & 0xffff)) >>> 0;
  }

  /**
   * Returns true if splitting is needed, that is when the current digest
   * reaches the given number of the same consecutive low bits.
   */
  split(mask: number): boolean {
    return ((this.s2 & (mask)) === mask);
  }

  clean() {
    this.reset();
  }
}



async function main(filename: string) {
  await sodium.ready;

  const seed = (new Uint8Array(32)).fill(12);

  const buf = fs.readFileSync(filename);
  const mask = (1 << 12) - 1;

  const minChunk = 1 << 14;
  const maxChunk = 1 << 21;

  function chunkify(buzhash: Buzhash | MovingSum | Rollsum, buf: Uint8Array, cb: (chunkStart: number, pos: number) => void) {
    buzhash.reset();
    let pos = buzhash.start(buf);
    let chunkStart = 0;
    while (pos < buf.length) {
      buzhash.update(buf, pos);
      if (pos - chunkStart >= minChunk) {
        if ((pos - chunkStart >= maxChunk) || (buzhash.split(mask))) {
          cb(chunkStart, pos);
          buzhash.reset();
          chunkStart = pos;
        }
      }
      pos++;
    }

    if (pos > chunkStart) {
      cb(chunkStart, pos);
    }
  }

  for (const buzhash of [new Buzhash(4096, seed), new MovingSum(8192, seed), new Rollsum(64, seed)]) {
    let paddedSize = 0;
    const chunks = {};
    chunkify(buzhash, buf, (chunkStart, pos) => {
      const hash = toBase64(sodium.crypto_hash(buf.subarray(chunkStart, pos)));
      chunks[hash] = (chunks[hash] ?? 0) + 1;
      const chunkPadding = getPadding(pos - chunkStart);
      paddedSize += chunkPadding;
      console.log(chunkStart.toLocaleString(), (pos - chunkStart).toLocaleString(), chunkPadding.toLocaleString());
    });

    // Remove a chunk around the start of the file:
    const biteStart = 10000;
    const biteSize = 210;
    const newBuf = new Uint8Array(buf.length - biteSize);
    newBuf.set(buf.subarray(0, biteStart));
    newBuf.set(buf.subarray(biteStart + biteSize), biteStart);

    newBuf[39000] = 0;
    newBuf[39001] = 1;
    newBuf[39002] = 2;
    newBuf[39003] = 3;
    newBuf[39004] = 4;

    const chunks2 = {};
    chunkify(buzhash, newBuf, (chunkStart, pos) => {
      const hash = toBase64(sodium.crypto_hash(newBuf.subarray(chunkStart, pos)));
      chunks2[hash] = (chunks2[hash] ?? 0) + 1;
      const chunkPadding = getPadding(pos - chunkStart);
      console.log(chunkStart.toLocaleString(), (pos - chunkStart).toLocaleString(), chunkPadding.toLocaleString());
    });

    let reused = 0;
    let replaced = 0;
    for (const chunk of Object.keys(chunks)) {
      if (chunks2[chunk]) {
        reused++;
      } else {
        replaced++;
      }
    }

    console.log(`${buzhash.constructor.name}: Reused ${reused} out of ${reused + replaced} (${reused / (reused + replaced) * 100}%). Average size: ${(buf.length / (reused + replaced)).toLocaleString()}. Padded vs orig: ${paddedSize / buf.length * 100}`);
  }
}

if (process.argv.length !== 3) {
  console.warn("Missing filename (first param)");
} else {
  main(process.argv[2]);
}
