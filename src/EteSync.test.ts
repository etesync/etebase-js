import 'whatwg-fetch';

import * as EteSync from './EteSync';

import { USER, EMAIL, KEY_B64 } from './TestConstants';

const testApiBase = 'http://localhost:12345';

let etesync: EteSync.Account;

async function verifyCollection(collectionManager: EteSync.CollectionManager, col: EteSync.EncryptedCollection, meta: EteSync.CollectionMetadata, content: Uint8Array) {
  collectionManager.verify(col);
  const decryptedMeta = await collectionManager.decryptMeta(col);
  expect(decryptedMeta).toEqual(meta);
  const decryptedContent = await collectionManager.decryptContent(col);
  expect(decryptedContent).toEqual(content);
}

async function verifyItem(itemManager: EteSync.CollectionItemManager, item: EteSync.EncryptedCollectionItem, meta: EteSync.CollectionItemMetadata, content: Uint8Array) {
  itemManager.verify(item);
  const decryptedMeta = await itemManager.decryptMeta(item);
  expect(decryptedMeta).toEqual(meta);
  const decryptedContent = await itemManager.decryptContent(item);
  expect(decryptedContent).toEqual(content);
}

beforeEach(async () => {
  await EteSync.ready;

  const user = {
    username: USER,
    email: EMAIL,
  };

  const accountData: EteSync.AccountData = {
    version: 1,
    key: KEY_B64,
    user,
    serverUrl: testApiBase,
  };
  etesync = EteSync.Account.load(accountData);
  await etesync.fetchToken();

  await fetch(testApiBase + '/api/v1/test/authentication/reset/', {
    method: 'post',
    headers: {
      'Content-Type': 'application/json;charset=UTF-8',
      'Authorization': 'Token ' + etesync.authToken,
    },
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

it('Simple item handling', async () => {
  const collectionManager = etesync.getCollectionManager();
  const colMeta: EteSync.CollectionMetadata = {
    type: 'COLTYPE',
    name: 'Calendar',
    description: 'Mine',
    color: '#ffffff',
  };

  const colContent = Uint8Array.from([1, 2, 3, 5]);
  const col = await collectionManager.create(colMeta, colContent);

  const itemManager = collectionManager.getItemManager(col);

  const meta: EteSync.CollectionItemMetadata = {
    type: 'ITEMTYPE',
  };
  const content = Uint8Array.from([1, 2, 3, 6]);

  const item = await itemManager.create(meta, content);
  await verifyItem(itemManager, item, meta, content);

  const meta2 = {
    type: 'ITEMTYPE',
    someval: 'someval',
  };
  await itemManager.update(item, meta2, content);

  await verifyItem(itemManager, item, meta2, content);
  expect(meta).not.toEqual(await collectionManager.decryptMeta(col));
});

it('Simple collection sync', async () => {
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

  {
    const collections = await collectionManager.list({ inline: true });
    expect(collections.length).toBe(0);
  }

  await collectionManager.upload(col);

  {
    const collections = await collectionManager.list({ inline: true });
    expect(collections.length).toBe(1);
    await verifyCollection(collectionManager, collections[0], meta, content);
  }

  const meta2 = {
    type: 'COLTYPE',
    name: 'Calendar2',
    description: 'Someone',
    color: '#000000',
  };
  await collectionManager.update(col, meta2, content);

  await collectionManager.upload(col);

  {
    const collections = await collectionManager.list({ inline: true });
    expect(collections.length).toBe(1);
    await verifyCollection(collectionManager, collections[0], meta2, content);
  }

  const content2 = Uint8Array.from([7, 2, 3, 5]);
  await collectionManager.update(col, meta2, content2);

  await collectionManager.upload(col);

  {
    const collections = await collectionManager.list({ inline: true });
    expect(collections.length).toBe(1);
    await verifyCollection(collectionManager, collections[0], meta2, content2);
  }
});

it('Simple item sync', async () => {
  const collectionManager = etesync.getCollectionManager();
  const colMeta: EteSync.CollectionMetadata = {
    type: 'COLTYPE',
    name: 'Calendar',
    description: 'Mine',
    color: '#ffffff',
  };

  const colContent = Uint8Array.from([1, 2, 3, 5]);
  const col = await collectionManager.create(colMeta, colContent);

  await collectionManager.upload(col);

  {
    const collections = await collectionManager.list({ inline: true });
    expect(collections.length).toBe(1);
  }

  const itemManager = collectionManager.getItemManager(col);

  const meta: EteSync.CollectionItemMetadata = {
    type: 'ITEMTYPE',
  };
  const content = Uint8Array.from([1, 2, 3, 6]);

  const item = await itemManager.create(meta, content);
  await verifyItem(itemManager, item, meta, content);

  await itemManager.upload([item]);

  {
    const items = await itemManager.list({ inline: true });
    expect(items.length).toBe(1);
    await verifyItem(itemManager, items[0], meta, content);
  }

  const meta2 = {
    type: 'ITEMTYPE',
    someval: 'someval',
  };
  await itemManager.update(item, meta2, content);

  await itemManager.upload([item]);

  {
    const items = await itemManager.list({ inline: true });
    expect(items.length).toBe(1);
    await verifyItem(itemManager, items[0], meta2, content);
  }

  const content2 = Uint8Array.from([7, 2, 3, 5]);
  await itemManager.update(item, meta2, content2);

  await itemManager.upload([item]);

  {
    const items = await itemManager.list({ inline: true });
    expect(items.length).toBe(1);
    await verifyItem(itemManager, items[0], meta2, content2);
  }
});

it('Item transactions', async () => {
  const collectionManager = etesync.getCollectionManager();
  const colMeta: EteSync.CollectionMetadata = {
    type: 'COLTYPE',
    name: 'Calendar',
    description: 'Mine',
    color: '#ffffff',
  };

  const colContent = Uint8Array.from([1, 2, 3, 5]);
  const col = await collectionManager.create(colMeta, colContent);

  await collectionManager.upload(col);

  {
    const collections = await collectionManager.list({ inline: true });
    expect(collections.length).toBe(1);
  }

  const itemManager = collectionManager.getItemManager(col);

  const meta: EteSync.CollectionItemMetadata = {
    type: 'ITEMTYPE',
  };
  const content = Uint8Array.from([1, 2, 3, 6]);

  const item = await itemManager.create(meta, content);

  const items: EteSync.EncryptedCollectionItem[] = [item];

  for (let i = 0 ; i < 5 ; i++) {
    const meta2 = {
      type: 'ITEMTYPE',
      someval: 'someval',
      i,
    };
    const content2 = Uint8Array.from([i, 7, 2, 3, 5]);
    const item2 = await itemManager.create(meta2, content2);
    items.push(item2);
  }

  await itemManager.transaction(items);

  {
    const items = await itemManager.list({ inline: true });
    expect(items.length).toBe(6);
  }

  // FIXME: add some cases where a transaction failes.
});
