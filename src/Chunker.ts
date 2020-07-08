/*
 * The rolling sum implementation is based on Rollsum from bup which is in turn based on rollsum from librsync:
 * https://github.com/bup/bup/blob/master/lib/bup/bupsplit.c
 * https://github.com/librsync/librsync/blob/master/src/rollsum.h
 *
 * We tried a few alternatives (see experiments/chunker/ for details) though this was by far the best one.
 *
 * The problem with using such a chunker is that it leaks information about the sizes of different chunks which
 * in turn leaks information about the original file (because the chunking is deterministic).
 * Therefore one needs to make sure to pad the chunks in a way that doesn't leak this information.
 */

const windowSize = 64;
const charOffset = 31;

export class Rollsum {
  private s1: number;
  private s2: number;
  private window: Uint8Array;
  private wofs: number;

  constructor() {

    this.window = new Uint8Array(windowSize);
    this.reset();
  }

  reset(): this {
    this.window.fill(0);
    this.s1 = windowSize * charOffset;
    this.s2 = windowSize * (windowSize - 1) * charOffset;
    this.wofs = 0;

    return this;
  }

  update(ch: number) {
    this.rollsumAdd(this.window[this.wofs], ch);
    this.window[this.wofs] = (ch);
    this.wofs = (this.wofs + 1) % windowSize;
  }

  private rollsumAdd(drop: number, add: number) {
    this.s1 = (this.s1 + add - drop) >>> 0;
    this.s2 = (this.s2 + this.s1 - (windowSize * (drop + charOffset))) >>> 0;
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
