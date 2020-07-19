import { CryptoManager, deriveKey, ready } from "./Crypto";
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

  const derived = cryptoManager.deriveSubkey(new Uint8Array(32));
  expect(derived).toEqual(fromBase64("4w-VCSTETv26JjVlVlD2VaACcb6aQSD2JbF-e89xnaA"));
});
