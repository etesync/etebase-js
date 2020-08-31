import { CryptoManager, deriveKey, ready, getPrettyFingerprint, CryptoMac } from "./Crypto";
import { USER } from "./TestConstants";

import { fromBase64, toBase64, fromString } from "./Helpers";
import { CURRENT_VERSION } from "./Constants";

it("Derive key", async () => {
  await ready;

  const derived = await deriveKey(fromBase64(USER.salt), USER.password);
  expect(toBase64(derived)).toBe(USER.key);
});

it("Symmetric encryption", () => {
  const key = fromBase64(USER.key);

  const cryptoManager = new CryptoManager(key, "Col", CURRENT_VERSION);
  const clearText = fromString("This Is Some Test Cleartext.");
  const cipher = cryptoManager.encrypt(clearText);
  expect(clearText).toEqual(cryptoManager.decrypt(cipher));

  const [mac, onlyCipher] = cryptoManager.encryptDetached(clearText);
  expect(clearText).toEqual(cryptoManager.decryptDetached(onlyCipher, mac));

  let derived = cryptoManager.deriveSubkey(new Uint8Array(32));
  expect(derived).toEqual(fromBase64("4w-VCSTETv26JjVlVlD2VaACcb6aQSD2JbF-e89xnaA"));

  derived = cryptoManager.calculateMac(new Uint8Array(32));
  expect(derived).toEqual(fromBase64("bz6eMZdAkIuiLUuFDiVwuH3IFs4hYkRfhzang_JzHr8"));

  derived = cryptoManager.calculateMac(new Uint8Array(32), false);
  expect(derived).toEqual(fromBase64("iesNaoppHa4s0V7QNpkxzgqUnsr6XD-T-BIYM2RuFcM"));

  const cryptoMac = cryptoManager.getCryptoMac();
  cryptoMac.update(new Uint8Array(4));
  expect(cryptoMac.finalize()).toEqual(fromBase64("y5nYZ75gDUna4bnaAHobXUlgQoTKOnueNW_KCYxcAg4"));
});

it("Crypto mac", () => {
  const key = fromBase64(USER.key);

  let cryptoMac = new CryptoMac(null);
  cryptoMac.update(new Uint8Array(4));
  cryptoMac.updateWithLenPrefix(new Uint8Array(8));
  expect(cryptoMac.finalize()).toEqual(fromBase64("P-Hpzo86RG6Ps4R1gGXmQrzmdJC2OotqqreKmB8G45A"));

  cryptoMac = new CryptoMac(key);
  cryptoMac.update(new Uint8Array(4));
  cryptoMac.updateWithLenPrefix(new Uint8Array(8));
  expect(cryptoMac.finalize()).toEqual(fromBase64("rgL6d_XDiBfbzevFdtktc61XB5-PkS1uQ1cj5DgfFc8"));
});

it("Pretty fingerprint", () => {
  const pubkey = fromBase64(USER.pubkey);

  const fingerprint = getPrettyFingerprint(pubkey);
  expect(fingerprint).toEqual("17756   37089   25897   42924\n06835   62184   63746   54689\n32947   01272   14138   19749\n00577   54359   44439   58177");
});
