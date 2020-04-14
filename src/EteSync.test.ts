import 'whatwg-fetch';

import * as EteSync from './EteSync';

import { USER, PASSWORD } from './TestConstants';

const testApiBase = 'http://localhost:12345';

let etesync: EteSync.EteSync;

async function verifyCollection(collectionManager: EteSync.CollectionManager, col: EteSync.EncryptedCollection, meta: EteSync.CollectionMetadata, content: Uint8Array) {
  collectionManager.verify(col);
  const decryptedMeta = await collectionManager.decryptMeta(col);
  expect(decryptedMeta).toEqual(meta);
  const decryptedContent = await collectionManager.decryptContent(col);
  expect(decryptedContent).toEqual(content);
}

beforeEach(async () => {
  await EteSync.ready;
  etesync = EteSync.EteSync.login(USER, PASSWORD, testApiBase);

  return;
  // FIXME: add this back once we actually test the server
  await fetch(testApiBase + '/reset/', {
    method: 'post',
    headers: { Authorization: 'Token ' + etesync.authToken },
  });
});

afterEach(async () => {
  etesync.logout();
});

it('Simple collection handling', async () => {
  const collectionManager = etesync.getCollectionManager();
  const meta: EteSync.CollectionMetadata = {
    type: 'COLTYPE',
    name: 'Calendar',
    description: 'Mine',
    color: '#ffffff',
  };

  const content = Uint8Array.from([1, 2, 3, 5]);
  const col = await collectionManager.create(meta, content);
  await verifyCollection(collectionManager, col, meta, content);

  const meta2 = {
    type: 'COLTYPE',
    name: 'Calendar2',
    description: 'Someone',
    color: '#000000',
  };
  await collectionManager.update(col, meta2, content);

  await verifyCollection(collectionManager, col, meta2, content);
  expect(meta).not.toEqual(await collectionManager.decryptMeta(col));
});
