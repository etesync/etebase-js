import { numToUint8Array, numFromUint8Array } from "./Helpers";

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
