import { CryptoManager, deriveKey, ready, sodium } from './Crypto';
import { PASSWORD, SALT_B64, KEY_B64 } from './TestConstants';

import { from_base64, to_base64 } from './Helpers';
import { CURRENT_VERSION } from './Constants';

it('Derive key', async () => {
  await ready;

  const derived = deriveKey(from_base64(SALT_B64), PASSWORD);
  expect(to_base64(derived)).toBe(KEY_B64);
});

it('Symmetric encryption', () => {
  const key = from_base64(KEY_B64);

  const cryptoManager = new CryptoManager(key, 'Col', CURRENT_VERSION);
  const clearText = sodium.from_string('This Is Some Test Cleartext.');
  const cipher = cryptoManager.encrypt(clearText);
  expect(clearText).toEqual(cryptoManager.decrypt(cipher));

  const [mac, onlyCipher] = cryptoManager.encryptDetached(clearText);
  expect(clearText).toEqual(cryptoManager.decryptDetached(onlyCipher, mac));
});
