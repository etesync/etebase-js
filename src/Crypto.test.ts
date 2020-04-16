import { CryptoManager, deriveKey, ready, sodium } from './Crypto';
import { PASSWORD, SALT_B64, KEY_B64 } from './TestConstants';

import { fromBase64, toBase64 } from './Helpers';
import { CURRENT_VERSION } from './Constants';

it('Derive key', async () => {
  await ready;

  const derived = deriveKey(fromBase64(SALT_B64), PASSWORD);
  expect(toBase64(derived)).toBe(KEY_B64);
});

it('Symmetric encryption', () => {
  const key = fromBase64(KEY_B64);

  const cryptoManager = new CryptoManager(key, 'Col', CURRENT_VERSION);
  const clearText = sodium.from_string('This Is Some Test Cleartext.');
  const cipher = cryptoManager.encrypt(clearText);
  expect(clearText).toEqual(cryptoManager.decrypt(cipher));

  const [mac, onlyCipher] = cryptoManager.encryptDetached(clearText);
  expect(clearText).toEqual(cryptoManager.decryptDetached(onlyCipher, mac));
});
