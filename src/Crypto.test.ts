import { CryptoManager, deriveKey, ready, sodium } from './Crypto';
import { USER } from './TestConstants';

import { fromBase64, toBase64 } from './Helpers';
import { CURRENT_VERSION } from './Constants';

it('Derive key', async () => {
  await ready;

  const derived = deriveKey(fromBase64(USER.saltB64), USER.password);
  expect(toBase64(derived)).toBe(USER.keyB64);
});

it('Symmetric encryption', () => {
  const key = fromBase64(USER.keyB64);

  const cryptoManager = new CryptoManager(key, 'Col', CURRENT_VERSION);
  const clearText = sodium.from_string('This Is Some Test Cleartext.');
  const cipher = cryptoManager.encrypt(clearText);
  expect(clearText).toEqual(cryptoManager.decrypt(cipher));

  const [mac, onlyCipher] = cryptoManager.encryptDetached(clearText);
  expect(clearText).toEqual(cryptoManager.decryptDetached(onlyCipher, mac));
});
