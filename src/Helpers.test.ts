import { numToUint8Array, numFromUint8Array, getPadding, shuffle, bufferPadFixed, bufferUnpadFixed } from "./Helpers";
import { ready } from "./Crypto";

it("Buffer to number", () => {
  const numbers = [
    0,
    123,
    12314,
    123123,
    4324234,
    32434234,
    2147483648,
    3352352352,
  ];

  for (const num of numbers) {
    const buf = numToUint8Array(num);
    expect(num).toEqual(numFromUint8Array(buf));
  }
});

it("Padding is larger than content", async () => {
  // Because of how we use padding (unpadding) we need to make sure padding is always larger than the content
  // Otherwise we risk the unpadder to fail thinking it should unpad when it shouldn't.

  for (let i = 1 ; i < (1 << 14) ; i++) {
    if (getPadding(i) <= i) {
      // Always fail here.
      expect(i).toEqual(-1);
    }
  }

  expect(getPadding(2343242)).toEqual(2359296);
});

it("Padding fixed size", async () => {
  await ready;

  const blocksize = 32;
  for (let i = 1 ; i < blocksize * 2 ; i++) {
    const buf = new Uint8Array(i);
    buf.fill(60);
    const padded = bufferPadFixed(buf, blocksize);
    const unpadded = bufferUnpadFixed(padded, blocksize);
    expect(unpadded).toEqual(buf);
  }
});

it("Shuffle", async () => {
  await ready;

  const len = 200;
  const shuffled = new Array(len);

  // Fill up with the indices
  for (let i = 0 ; i < len ; i++) {
    shuffled[i] = i;
  }

  const indices = shuffle(shuffled);

  // Unshuffle
  for (let i = 0 ; i < len ; i++) {
    expect(shuffled[indices[i]]).toEqual(i);
  }
});
