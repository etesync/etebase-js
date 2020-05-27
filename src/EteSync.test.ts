import 'whatwg-fetch';

import * as EteSync from './EteSync';

import { USER, USER2 } from './TestConstants';
import { CURRENT_VERSION } from './Constants';

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

async function prepareUserForTest(user: typeof USER) {
  const accountData: EteSync.AccountData = {
    version: CURRENT_VERSION,
    key: user.keyB64,
    user,
    serverUrl: testApiBase,
  };
  const etesync = EteSync.Account.load(accountData);
  await etesync.fetchToken();

  await fetch(testApiBase + '/api/v1/test/authentication/reset/', {
    method: 'post',
    headers: {
      'Content-Type': 'application/json;charset=UTF-8',
      'Authorization': 'Token ' + etesync.authToken,
    },
  });

  return etesync;
}

beforeEach(async () => {
  await EteSync.ready;

  etesync = await prepareUserForTest(USER);
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

  await itemManager.batch([item]);

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

  await itemManager.batch([item]);

  {
    const items = await itemManager.list({ inline: true });
    expect(items.length).toBe(1);
    await verifyItem(itemManager, items[0], meta2, content);
  }

  const content2 = Uint8Array.from([7, 2, 3, 5]);
  await itemManager.update(item, meta2, content2);

  await itemManager.batch([item]);

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

  const deps: EteSync.EncryptedCollectionItem[] = [item];

  await itemManager.transaction(deps);
  const itemOld = await itemManager.fetch(item.uid, { inline: true });

  const items: EteSync.EncryptedCollectionItem[] = [];

  {
    const items = await itemManager.list({ inline: true });
    expect(items.length).toBe(1);
  }

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

  await itemManager.transaction(items, deps);

  {
    const items = await itemManager.list({ inline: true });
    expect(items.length).toBe(6);
  }

  {
    const meta3 = { ...meta, someval: 'some' };
    await itemManager.update(item, meta3, content);
  }

  await itemManager.transaction([item], items);

  {
    const items = await itemManager.list({ inline: true });
    expect(items.length).toBe(6);
  }

  {
    const meta3 = { ...meta, someval: 'some2' };
    await itemManager.update(item, meta3, content);

    // Old in the deps
    await expect(itemManager.transaction([item], [...items, itemOld])).rejects.toBeInstanceOf(EteSync.HTTPError);

    const itemOld2 = EteSync.EncryptedCollectionItem.deserialize(itemOld.serialize());

    await itemManager.transaction([item]);

    await itemManager.update(itemOld2, meta3, content);

    // Old stoken in the item itself
    await expect(itemManager.transaction([itemOld2])).rejects.toBeInstanceOf(EteSync.HTTPError);
  }

  {
    const meta3 = { ...meta, someval: 'some2' };
    const item2 = await itemManager.fetch(items[0].uid, { inline: true });
    await itemManager.update(item2, meta3, content);

    const itemOld2 = EteSync.EncryptedCollectionItem.deserialize(itemOld.serialize());
    await itemManager.update(itemOld2, meta3, content);

    // Part of the transaction is bad, and part is good
    await expect(itemManager.transaction([item2, itemOld2])).rejects.toBeInstanceOf(EteSync.HTTPError);

    // Verify it hasn't changed after the transaction above failed
    const item2Fetch = await itemManager.fetch(item2.uid, { inline: true });
    expect(item2Fetch.serialize()).not.toEqual(item2.serialize());
  }

  {
    // Global stoken test
    const meta3 = { ...meta, someval: 'some2' };
    await itemManager.update(item, meta3, content);

    const newCol = await collectionManager.fetch(col.uid, { inline: true });
    const stoken = newCol.stoken;
    const badEtag = col.etag;

    await expect(itemManager.transaction([item], undefined, { stoken: badEtag })).rejects.toBeInstanceOf(EteSync.HTTPError);

    await itemManager.transaction([item], undefined, { stoken });
  }
});

it('Item batch stoken', async () => {
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

  await itemManager.batch([item]);

  const items: EteSync.EncryptedCollectionItem[] = [];

  {
    const items = await itemManager.list({ inline: true });
    expect(items.length).toBe(1);
  }

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

  await itemManager.batch(items);

  {
    const meta3 = { ...meta, someval: 'some2' };
    const item2 = EteSync.EncryptedCollectionItem.deserialize(item.serialize());

    await itemManager.update(item2, meta3, content);
    await itemManager.batch([item2]);

    meta3.someval = 'some3';
    await itemManager.update(item, meta3, content);

    // Old stoken in the item itself should work for batch and fail for transaction
    await expect(itemManager.transaction([item])).rejects.toBeInstanceOf(EteSync.HTTPError);
    await itemManager.batch([item]);
  }

  {
    // Global stoken test
    const meta3 = { ...meta, someval: 'some2' };
    await itemManager.update(item, meta3, content);

    const newCol = await collectionManager.fetch(col.uid, { inline: true });
    const stoken = newCol.stoken;
    const badEtag = col.etag;

    await expect(itemManager.batch([item], { stoken: badEtag })).rejects.toBeInstanceOf(EteSync.HTTPError);

    await itemManager.batch([item], { stoken });
  }
});

it('Item fetch updates', async () => {
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

  await itemManager.batch([item]);

  const items: EteSync.EncryptedCollectionItem[] = [];

  {
    const items = await itemManager.list({ inline: true });
    expect(items.length).toBe(1);
  }

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

  await itemManager.batch(items);

  {
    const items = await itemManager.list({ inline: true });
    expect(items.length).toBe(6);
  }


  let stoken: string | null = null;

  {
    const newCol = await collectionManager.fetch(col.uid, { inline: true });
    stoken = newCol.stoken;
  }

  {
    let updates = await itemManager.fetchUpdates(items);
    expect(updates.length).toBe(0);

    updates = await itemManager.fetchUpdates(items, { stoken });
    expect(updates.length).toBe(0);
  }

  {
    const meta3 = { ...meta, someval: 'some2' };
    const item2 = EteSync.EncryptedCollectionItem.deserialize(items[0].serialize());

    await itemManager.update(item2, meta3, content);
    await itemManager.batch([item2]);
  }

  {
    let updates = await itemManager.fetchUpdates(items);
    expect(updates.length).toBe(1);

    updates = await itemManager.fetchUpdates(items, { stoken });
    expect(updates.length).toBe(1);
  }

  {
    const item2 = await itemManager.fetch(items[0].uid, { inline: true });
    let updates = await itemManager.fetchUpdates([item2]);
    expect(updates.length).toBe(0);

    updates = await itemManager.fetchUpdates([item2], { stoken });
    expect(updates.length).toBe(1);
  }

  {
    const newCol = await collectionManager.fetch(col.uid, { inline: true });
    stoken = newCol.stoken;
  }

  {
    const updates = await itemManager.fetchUpdates(items, { stoken });
    expect(updates.length).toBe(0);
  }
});

it('Collection invitations', async () => {
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

  const items: EteSync.EncryptedCollectionItem[] = [];

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

  await itemManager.batch(items);

  const collectionInvitationManager = new EteSync.CollectionInvitationManager(etesync);

  const etesync2 = await prepareUserForTest(USER2);
  const collectionManager2 = etesync2.getCollectionManager();

  const user2Profile = await collectionInvitationManager.fetchUserProfile(USER2.username);

  await collectionInvitationManager.invite(col, USER2.username, user2Profile.pubkey, EteSync.CollectionAccessLevel.ReadWrite);

  const collectionInvitationManager2 = new EteSync.CollectionInvitationManager(etesync2);

  let invitations = await collectionInvitationManager2.list();
  expect(invitations.length).toBe(1);

  await collectionInvitationManager2.reject(invitations[0]);

  {
    const collections = await collectionManager2.list({ inline: true });
    expect(collections.length).toBe(0);
  }

  {
    const invitations = await collectionInvitationManager2.list();
    expect(invitations.length).toBe(0);
  }

  // Invite and then disinvite
  await collectionInvitationManager.invite(col, USER2.username, user2Profile.pubkey, EteSync.CollectionAccessLevel.ReadWrite);

  invitations = await collectionInvitationManager2.list();
  expect(invitations.length).toBe(1);

  await collectionInvitationManager2.reject(invitations[0]);

  {
    const collections = await collectionManager2.list({ inline: true });
    expect(collections.length).toBe(0);
  }

  {
    const invitations = await collectionInvitationManager2.list();
    expect(invitations.length).toBe(0);
  }


  // Invite again, this time accept
  await collectionInvitationManager.invite(col, USER2.username, user2Profile.pubkey, EteSync.CollectionAccessLevel.ReadWrite);

  invitations = await collectionInvitationManager2.list();
  expect(invitations.length).toBe(1);

  await collectionInvitationManager2.accept(invitations[0]);

  {
    const collections = await collectionManager2.list({ inline: true });
    expect(collections.length).toBe(1);

    await collectionManager2.decryptMeta(collections[0]);
  }

  {
    const invitations = await collectionInvitationManager2.list();
    expect(invitations.length).toBe(0);
  }

  etesync2.logout();
});
