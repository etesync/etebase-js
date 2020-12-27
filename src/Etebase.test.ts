import request from "./Request";

import * as Etebase from "./Etebase";

import { USER, USER2, sessionStorageKey } from "./TestConstants";

import { Authenticator, PrefetchOption } from "./OnlineManagers";
import { fromBase64, fromString, msgpackEncode, msgpackDecode, randomBytesDeterministic, toBase64 } from "./Helpers";

const testApiBase = process.env.ETEBASE_TEST_API_URL ?? "http://localhost:8033";

let etebase: Etebase.Account;

const colType = "some.coltype";

async function verifyCollection<T>(col: Etebase.Collection, meta: Etebase.ItemMetadata<T>, content: Uint8Array) {
  col.verify();
  const decryptedMeta = col.getMeta();
  expect(decryptedMeta).toEqual(meta);
  const decryptedContent = await col.getContent();
  expect(toBase64(decryptedContent)).toEqual(toBase64(content));
}

async function verifyItem<T>(item: Etebase.Item, meta: Etebase.ItemMetadata<T>, content: Uint8Array) {
  item.verify();
  const decryptedMeta = item.getMeta();
  expect(decryptedMeta).toEqual(meta);
  const decryptedContent = await item.getContent();
  expect(toBase64(decryptedContent)).toEqual(toBase64(content));
}

async function prepareUserForTest(user: typeof USER) {
  const response = await request(testApiBase + "/api/v1/test/authentication/reset/", {
    method: "post",
    headers: {
      "Accept": "application/msgpack",
      "Content-Type": "application/msgpack",
    },

    body: msgpackEncode({
      user: {
        username: user.username,
        email: user.email,
      },
      salt: fromBase64(user.salt),
      loginPubkey: fromBase64(user.loginPubkey),
      encryptedContent: fromBase64(user.encryptedContent),
      pubkey: fromBase64(user.pubkey),
    }),
  });

  if (!response.ok) {
    throw new Error(response.statusText);
  }

  const etebase = await Etebase.Account.restore(user.storedSession, fromBase64(sessionStorageKey));
  etebase.serverUrl = testApiBase;
  await etebase.fetchToken();

  return etebase;
}

beforeAll(async () => {
  await Etebase.ready;

  for (const user of [USER, USER2]) {
    try {
      const authenticator = new Authenticator(testApiBase);
      await authenticator.signup(user, fromBase64(user.salt), fromBase64(user.loginPubkey), fromBase64(user.pubkey), fromBase64(user.encryptedContent));
    } catch (e) {
      //
    }
  }
});

beforeEach(async () => {
  await Etebase.ready;

  etebase = await prepareUserForTest(USER);
});

afterEach(async () => {
  await etebase.logout();
});

it("Check server is etebase", async () => {
  expect(await Etebase.Account.isEtebaseServer(testApiBase)).toBeTruthy();
  expect(await Etebase.Account.isEtebaseServer(testApiBase + "/api/")).toBeFalsy();
  await expect(Etebase.Account.isEtebaseServer("http://doesnotexist")).rejects.toBeInstanceOf(Error);
  await expect(Etebase.Account.login(USER2.username, USER2.password, testApiBase + "/api/")).rejects.toBeInstanceOf(Etebase.NotFoundError);
});

it("Getting dashboard url", async () => {
  let url: string | undefined;
  try {
    url = await etebase.getDashboardUrl();
  } catch (e) {
    expect(e).toBeInstanceOf(Etebase.HttpError);
    expect((e as Etebase.HttpError).content?.code).toEqual("not_supported");
  }
  if (url !== undefined) {
    expect(url).toBeTruthy();
  }
});

it("Simple collection handling", async () => {
  const collectionManager = etebase.getCollectionManager();
  const meta: Etebase.ItemMetadata = {
    name: "Calendar",
    description: "Mine",
    color: "#ffffff",
  };

  const content = Uint8Array.from([1, 2, 3, 5]);
  const col = await collectionManager.create(colType, meta, content);
  expect(col.getCollectionType()).toEqual(colType);
  await verifyCollection(col, meta, content);

  const meta2 = {
    name: "Calendar2",
    description: "Someone",
    color: "#000000",
  };
  col.setMeta(meta2);

  await verifyCollection(col, meta2, content);
  expect(meta).not.toEqual(col.getMeta());

  expect(col.isDeleted).toBeFalsy();
  col.delete(true);
  expect(col.isDeleted).toBeTruthy();
  await verifyCollection(col, meta2, content);
});

it("Simple item handling", async () => {
  const collectionManager = etebase.getCollectionManager();
  const colMeta: Etebase.ItemMetadata = {
    name: "Calendar",
    description: "Mine",
    color: "#ffffff",
  };

  const colContent = Uint8Array.from([1, 2, 3, 5]);
  const col = await collectionManager.create(colType, colMeta, colContent);

  const itemManager = collectionManager.getItemManager(col);

  const meta: Etebase.ItemMetadata = {
    type: "ITEMTYPE",
  };
  const content = Uint8Array.from([1, 2, 3, 6]);

  const item = await itemManager.create(meta, content);
  await verifyItem(item, meta, content);

  const meta2 = {
    type: "ITEMTYPE",
    someval: "someval",
  };
  item.setMeta(meta2);

  await verifyItem(item, meta2, content);
  expect(meta).not.toEqual(col.getMeta());

  expect(item.isDeleted).toBeFalsy();
  item.delete(true);
  expect(item.isDeleted).toBeTruthy();
  await verifyItem(item, meta2, content);
});

it("Content formats", async () => {
  const collectionManager = etebase.getCollectionManager();
  const meta: Etebase.ItemMetadata = {
    name: "Calendar",
    description: "Mine",
    color: "#ffffff",
  };

  const content = "Hello";
  const col = await collectionManager.create(colType, meta, content);
  {
    const decryptedContent = await col.getContent(Etebase.OutputFormat.String);
    expect(decryptedContent).toEqual(content);

    const decryptedContentUint = await col.getContent();
    expect(decryptedContentUint).toEqual(fromString(content));
  }

  const itemManager = collectionManager.getItemManager(col);

  const metaItem: Etebase.ItemMetadata = {
    type: "ITEMTYPE",
  };
  const content2 = "Hello2";

  const item = await itemManager.create(metaItem, content2);
  {
    const decryptedContent = await item.getContent(Etebase.OutputFormat.String);
    expect(decryptedContent).toEqual(content2);

    const decryptedContentUint = await item.getContent();
    expect(decryptedContentUint).toEqual(fromString(content2));
  }
});

it("Simple collection sync", async () => {
  const collectionManager = etebase.getCollectionManager();
  const meta: Etebase.ItemMetadata = {
    name: "Calendar",
    description: "Mine",
    color: "#ffffff",
  };

  const content = Uint8Array.from([1, 2, 3, 5]);
  let col = await collectionManager.create(colType, meta, content);
  await verifyCollection(col, meta, content);

  {
    const collections = await collectionManager.list(colType);
    expect(collections.data.length).toBe(0);
  }

  await collectionManager.upload(col);

  {
    const collections = await collectionManager.list(colType);
    expect(collections.data.length).toBe(1);
    await verifyCollection(collections.data[0], meta, content);
  }

  {
    col = await collectionManager.fetch(col.uid);
    const collections = await collectionManager.list(colType, { stoken: col.stoken });
    expect(collections.data.length).toBe(0);
  }

  const colOld = await collectionManager.fetch(col.uid);

  const meta2 = {
    name: "Calendar2",
    description: "Someone",
    color: "#000000",
  };
  col.setMeta(meta2);

  await collectionManager.upload(col);

  {
    const collections = await collectionManager.list(colType);
    expect(collections.data.length).toBe(1);
    await verifyCollection(collections.data[0], meta2, content);
  }

  {
    const collections = await collectionManager.list(colType, { stoken: col.stoken });
    expect(collections.data.length).toBe(1);
  }

  // Fail uploading because of an old stoken/etag
  {
    const content2 = Uint8Array.from([7, 2, 3, 5]);
    await colOld.setContent(content2);

    await expect(collectionManager.transaction(colOld)).rejects.toBeInstanceOf(Etebase.ConflictError);

    await expect(collectionManager.upload(colOld, { stoken: colOld.stoken })).rejects.toBeInstanceOf(Etebase.ConflictError);
  }

  const content2 = Uint8Array.from([7, 2, 3, 5]);
  await col.setContent(content2);

  await collectionManager.upload(col);

  {
    const collections = await collectionManager.list(colType);
    expect(collections.data.length).toBe(1);
    await verifyCollection(collections.data[0], meta2, content2);
  }

  // Try uploadign the same collection twice as new
  col = await collectionManager.create(colType, meta, content);
  const cachedCollection = collectionManager.cacheSave(col);
  const colCopy = collectionManager.cacheLoad(cachedCollection);
  await colCopy.setContent("Something else"); // Just so it has a different revision uid
  await collectionManager.upload(col);
  await expect(collectionManager.upload(colCopy)).rejects.toBeInstanceOf(Etebase.ConflictError);
});

it("Collection types", async () => {
  const collectionManager = etebase.getCollectionManager();
  const meta: Etebase.ItemMetadata = {
    name: "Calendar",
    description: "Mine",
    color: "#ffffff",
  };

  const content = Uint8Array.from([1, 2, 3, 5]);
  const col = await collectionManager.create(colType, meta, content);
  await verifyCollection(col, meta, content);

  {
    const collections = await collectionManager.list(colType);
    expect(collections.data.length).toBe(0);
  }

  await collectionManager.upload(col);

  {
    const collections = await collectionManager.list(colType);
    expect(collections.data.length).toBe(1);
    await verifyCollection(collections.data[0], meta, content);
  }

  {
    const collections = await collectionManager.list("bad.coltype");
    expect(collections.data.length).toBe(0);
  }

  {
    const collections = await collectionManager.list(["bad.coltype", colType, "anotherbad"]);
    expect(collections.data.length).toBe(1);
  }

  {
    const collections = await collectionManager.list(["bad.coltype", "anotherbad"]);
    expect(collections.data.length).toBe(0);
  }
});


it("Simple item sync", async () => {
  const collectionManager = etebase.getCollectionManager();
  const colMeta: Etebase.ItemMetadata = {
    name: "Calendar",
    description: "Mine",
    color: "#ffffff",
  };

  const colContent = Uint8Array.from([1, 2, 3, 5]);
  const col = await collectionManager.create(colType, colMeta, colContent);

  await collectionManager.upload(col);

  {
    const collections = await collectionManager.list(colType);
    expect(collections.data.length).toBe(1);
  }

  const itemManager = collectionManager.getItemManager(col);

  const meta: Etebase.ItemMetadata = {
    type: "ITEMTYPE",
  };
  const content = Uint8Array.from([1, 2, 3, 6]);

  const item = await itemManager.create(meta, content);
  await verifyItem(item, meta, content);

  await itemManager.batch([item]);

  {
    const items = await itemManager.list();
    expect(items.data.length).toBe(1);
    await verifyItem(items.data[0], meta, content);
  }

  const meta2 = {
    type: "ITEMTYPE",
    someval: "someval",
  };
  item.setMeta(meta2);

  await itemManager.batch([item]);

  {
    const items = await itemManager.list();
    expect(items.data.length).toBe(1);
    await verifyItem(items.data[0], meta2, content);
  }

  const content2 = Uint8Array.from([7, 2, 3, 5]);
  await item.setContent(content2);

  await itemManager.batch([item]);

  {
    const items = await itemManager.list();
    expect(items.data.length).toBe(1);
    await verifyItem(items.data[0], meta2, content2);
  }
});

it("Item re-uploaded revisions", async () => {
  const collectionManager = etebase.getCollectionManager();
  const colMeta: Etebase.ItemMetadata = {
    name: "Calendar",
    description: "Mine",
    color: "#ffffff",
  };

  const col = await collectionManager.create(colType, colMeta, "");
  await collectionManager.upload(col);


  const itemManager = collectionManager.getItemManager(col);

  const meta: Etebase.ItemMetadata = {
    type: "ITEMTYPE",
  };

  const item = await itemManager.create(meta, "");

  await itemManager.batch([item]);
  // Adding the same item twice should work
  await itemManager.batch([item]);

  const itemOld = item._clone();

  await item.setContent("Test");
  await itemManager.batch([item]);

  await expect(itemManager.batch([itemOld])).rejects.toBeInstanceOf(Etebase.HttpError);
});

it("Collection as item", async () => {
  const collectionManager = etebase.getCollectionManager();
  const colMeta: Etebase.ItemMetadata = {
    name: "Calendar",
    description: "Mine",
    color: "#ffffff",
  };

  const colContent = Uint8Array.from([1, 2, 3, 5]);
  const col = await collectionManager.create(colType, colMeta, colContent);

  await collectionManager.upload(col);

  {
    const collections = await collectionManager.list(colType);
    expect(collections.data.length).toBe(1);
  }

  const itemManager = collectionManager.getItemManager(col);

  // Verify withCollection works
  {
    let items = await itemManager.list();
    expect(items.data.length).toBe(0);
    items = await itemManager.list({ withCollection: true });
    expect(items.data.length).toBe(1);
    await verifyItem(items.data[0], colMeta, colContent);
  }

  const meta: Etebase.ItemMetadata = {
    type: "ITEMTYPE",
  };
  const content = Uint8Array.from([1, 2, 3, 6]);

  const item = await itemManager.create(meta, content);
  await verifyItem(item, meta, content);

  await itemManager.batch([item]);

  {
    let items = await itemManager.list();
    expect(items.data.length).toBe(1);
    items = await itemManager.list({ withCollection: true });
    expect(items.data.length).toBe(2);
    await verifyItem(items.data[0], colMeta, colContent);
  }

  const colItemOld = await itemManager.fetch(col.uid);

  // Manipulate the collection with batch/transaction
  await col.setContent("test");

  await itemManager.batch([col.item]);

  {
    const collections = await collectionManager.list(colType);
    expect(collections.data.length).toBe(1);
    await verifyCollection(collections.data[0], colMeta, fromString("test"));
  }

  await col.setContent("test2");

  await itemManager.transaction([col.item]);

  {
    const collections = await collectionManager.list(colType);
    expect(collections.data.length).toBe(1);
    await verifyCollection(collections.data[0], colMeta, fromString("test2"));
  }

  {
    const updates = await itemManager.fetchUpdates([colItemOld, item]);
    expect(updates.data.length).toBe(1);
    await verifyItem(updates.data[0], colMeta, fromString("test2"));
  }
});

// Verify we prevent users from trying to use the wrong items in the API
it("Item multiple collections", async () => {
  const collectionManager = etebase.getCollectionManager();

  const colMeta: Etebase.ItemMetadata = {
    name: "Calendar",
    description: "Mine",
    color: "#ffffff",
  };

  const colContent = Uint8Array.from([1, 2, 3, 5]);
  const col = await collectionManager.create(colType, colMeta, colContent);

  await collectionManager.upload(col);

  const colMeta2: Etebase.ItemMetadata = {
    name: "Calendar 2",
    description: "Mine",
    color: "#ffffff",
  };

  const colContent2 = Uint8Array.from([]);
  const col2 = await collectionManager.create(colType, colMeta2, colContent2);

  await collectionManager.upload(col2);

  {
    const collections = await collectionManager.list(colType);
    expect(collections.data.length).toBe(2);
  }

  const itemManager = collectionManager.getItemManager(col);
  const itemManager2 = collectionManager.getItemManager(col2);

  const meta: Etebase.ItemMetadata = {
    type: "ITEMTYPE",
  };
  const content = Uint8Array.from([1, 2, 3, 6]);

  const item = await itemManager.create(meta, content);
  await verifyItem(item, meta, content);

  // With the bad item as the main
  await itemManager.batch([item]);
  await expect(itemManager2.batch([item])).rejects.toBeInstanceOf(Etebase.ProgrammingError);
  await expect(itemManager2.transaction([item])).rejects.toBeInstanceOf(Etebase.ProgrammingError);

  // With the bad item as a dep
  const item2 = await itemManager2.create(meta, "col2");
  await expect(itemManager2.batch([item2], [item])).rejects.toBeInstanceOf(Etebase.ProgrammingError);
  await expect(itemManager2.transaction([item2], [item])).rejects.toBeInstanceOf(Etebase.ProgrammingError);
  await itemManager2.batch([item2]);

  await itemManager.fetchUpdates([item]);
  await expect(itemManager.fetchUpdates([item, item2])).rejects.toBeInstanceOf(Etebase.ProgrammingError);

  // Verify we also set it correctly when fetched
  {
    const items = await itemManager.list();
    const itemFetched = items.data[0];
    expect(item.collectionUid).toEqual(itemFetched.collectionUid);
  }
  {
    const itemFetched = await itemManager.fetch(item.uid);
    expect(item.collectionUid).toEqual(itemFetched.collectionUid);
  }
});

it("Collection and item deletion", async () => {
  const collectionManager = etebase.getCollectionManager();
  const colMeta: Etebase.ItemMetadata = {
    name: "Calendar",
    description: "Mine",
    color: "#ffffff",
  };

  const colContent = Uint8Array.from([1, 2, 3, 5]);
  const col = await collectionManager.create(colType, colMeta, colContent);
  await verifyCollection(col, colMeta, colContent);

  await collectionManager.upload(col);

  const collections = await collectionManager.list(colType);

  const itemManager = collectionManager.getItemManager(col);
  const meta: Etebase.ItemMetadata = {
    type: "ITEMTYPE",
  };
  const content = Uint8Array.from([1, 2, 3, 6]);

  const item = await itemManager.create(meta, content);
  await verifyItem(item, meta, content);

  await itemManager.batch([item]);

  const items = await itemManager.list();
  expect(items.data.length).toBe(1);

  item.delete(true);
  await itemManager.batch([item]);

  {
    const items2 = await itemManager.list({ stoken: items.stoken });
    expect(items2.data.length).toBe(1);

    const item2 = items2.data[0];

    await verifyItem(item2, meta, content);
    expect(item2.isDeleted).toBeTruthy();
  }

  col.delete(true);
  await collectionManager.upload(col);

  {
    const collections2 = await collectionManager.list(colType, { stoken: collections.stoken });
    expect(collections2.data.length).toBe(1);

    const col2 = collections2.data[0];

    await verifyCollection(col2, colMeta, colContent);
    expect(col2.isDeleted).toBeTruthy();
  }
});

it("Empty content", async () => {
  const collectionManager = etebase.getCollectionManager();
  const meta: Etebase.ItemMetadata = {
    name: "Calendar",
    description: "Mine",
    color: "#ffffff",
  };

  const content = Uint8Array.from([]);
  let col = await collectionManager.create(colType, meta, content);
  await verifyCollection(col, meta, content);
  await collectionManager.upload(col);

  {
    col = await collectionManager.fetch(col.uid);
    await verifyCollection(col, meta, content);
  }

  const itemManager = collectionManager.getItemManager(col);

  const itemMeta: Etebase.ItemMetadata = {
    type: "ITEMTYPE",
  };
  const item = await itemManager.create(itemMeta, content);

  await itemManager.transaction([item]);

  {
    const items = await itemManager.list();
    const itemFetched = items.data[0];
    verifyItem(itemFetched, itemMeta, content);
  }
});

it("List response correctness", async () => {
  const collectionManager = etebase.getCollectionManager();
  const colMeta: Etebase.ItemMetadata = {
    name: "Calendar",
    description: "Mine",
    color: "#ffffff",
  };

  const colContent = Uint8Array.from([1, 2, 3, 5]);
  const col = await collectionManager.create(colType, colMeta, colContent);

  await collectionManager.upload(col);

  const collections = await collectionManager.list(colType);
  expect(collections.data.length).toBe(1);

  const itemManager = collectionManager.getItemManager(col);

  const items: Etebase.Item[] = [];

  for (let i = 0 ; i < 5 ; i++) {
    const meta2 = {
      type: "ITEMTYPE",
      someval: "someval",
      i,
    };
    const content2 = Uint8Array.from([i, 7, 2, 3, 5]);
    const item2 = await itemManager.create(meta2, content2);
    items.push(item2);
  }

  await itemManager.batch(items);

  {
    let items = await itemManager.list();
    expect(items.data.length).toBe(5);
    expect(items.done).toBeTruthy();
    items = await itemManager.list({ limit: 5 });
    expect(items.done).toBeTruthy();
  }

  let stoken: string | null = null;
  for (let i = 0 ; i < 3 ; i++) {
    const items = await itemManager.list({ limit: 2, stoken });
    expect(items.done).toBe(i === 2);
    stoken = items.stoken as string;
  }

  // Also check collections
  {
    for (let i = 0 ; i < 4 ; i++) {
      const content2 = Uint8Array.from([i, 7, 2, 3, 5]);
      const col2 = await collectionManager.create(colType, colMeta, content2);
      await collectionManager.upload(col2);
    }
  }

  {
    let collections = await collectionManager.list(colType);
    expect(collections.data.length).toBe(5);
    expect(collections.done).toBeTruthy();
    collections = await collectionManager.list(colType, { limit: 5 });
    expect(collections.done).toBeTruthy();
  }

  stoken = null;
  for (let i = 0 ; i < 3 ; i++) {
    const collections = await collectionManager.list(colType, { limit: 2, stoken });
    expect(collections.done).toBe(i === 2);
    stoken = collections.stoken as string;
  }
});

it("Item transactions", async () => {
  const collectionManager = etebase.getCollectionManager();
  const colMeta: Etebase.ItemMetadata = {
    name: "Calendar",
    description: "Mine",
    color: "#ffffff",
  };

  const colContent = Uint8Array.from([1, 2, 3, 5]);
  const col = await collectionManager.create(colType, colMeta, colContent);

  await collectionManager.upload(col);

  {
    const collections = await collectionManager.list(colType);
    expect(collections.data.length).toBe(1);
  }

  const itemManager = collectionManager.getItemManager(col);

  const meta: Etebase.ItemMetadata = {
    type: "ITEMTYPE",
  };
  const content = Uint8Array.from([1, 2, 3, 6]);

  const item = await itemManager.create(meta, content);

  const deps: Etebase.Item[] = [item];

  await itemManager.transaction(deps);
  const itemOld = await itemManager.fetch(item.uid);

  const items: Etebase.Item[] = [];

  {
    const items = await itemManager.list();
    expect(items.data.length).toBe(1);
  }

  for (let i = 0 ; i < 5 ; i++) {
    const meta2 = {
      type: "ITEMTYPE",
      someval: "someval",
      i,
    };
    const content2 = Uint8Array.from([i, 7, 2, 3, 5]);
    const item2 = await itemManager.create(meta2, content2);
    items.push(item2);
  }

  await itemManager.transaction(items, deps);

  {
    const items = await itemManager.list();
    expect(items.data.length).toBe(6);
  }

  {
    const meta3 = { ...meta, someval: "some" };
    item.setMeta(meta3);
  }

  await itemManager.transaction([item], items);

  {
    const items = await itemManager.list();
    expect(items.data.length).toBe(6);
  }

  {
    const meta3 = { ...meta, someval: "some2" };
    item.setMeta(meta3);

    // Old in the deps
    await expect(itemManager.transaction([item], [...items, itemOld])).rejects.toBeInstanceOf(Etebase.ConflictError);

    const itemOld2 = itemOld._clone();

    await itemManager.transaction([item]);

    itemOld2.setMeta(meta3);

    // Old stoken in the item itself
    await expect(itemManager.transaction([itemOld2])).rejects.toBeInstanceOf(Etebase.ConflictError);
  }

  {
    const meta3 = { ...meta, someval: "some2" };
    const item2 = await itemManager.fetch(items[0].uid);
    item2.setMeta(meta3);

    const itemOld2 = itemOld._clone();
    itemOld2.setMeta(meta3);

    // Part of the transaction is bad, and part is good
    await expect(itemManager.transaction([item2, itemOld2])).rejects.toBeInstanceOf(Etebase.ConflictError);

    // Verify it hasn't changed after the transaction above failed
    const item2Fetch = await itemManager.fetch(item2.uid);
    expect(item2Fetch.getMeta()).not.toEqual(item2.getMeta());
  }

  {
    // Global stoken test
    const meta3 = { ...meta, someval: "some2" };
    item.setMeta(meta3);

    const newCol = await collectionManager.fetch(col.uid);
    const stoken = newCol.stoken;
    const badEtag = col.etag;

    await expect(itemManager.transaction([item], undefined, { stoken: badEtag })).rejects.toBeInstanceOf(Etebase.ConflictError);

    await itemManager.transaction([item], undefined, { stoken });
  }
});

it("Item batch stoken", async () => {
  const collectionManager = etebase.getCollectionManager();
  const colMeta: Etebase.ItemMetadata = {
    name: "Calendar",
    description: "Mine",
    color: "#ffffff",
  };

  const colContent = Uint8Array.from([1, 2, 3, 5]);
  const col = await collectionManager.create(colType, colMeta, colContent);

  await collectionManager.upload(col);

  {
    const collections = await collectionManager.list(colType);
    expect(collections.data.length).toBe(1);
  }

  const itemManager = collectionManager.getItemManager(col);

  const meta: Etebase.ItemMetadata = {
    type: "ITEMTYPE",
  };
  const content = Uint8Array.from([1, 2, 3, 6]);

  const item = await itemManager.create(meta, content);

  await itemManager.batch([item]);

  const items: Etebase.Item[] = [];

  {
    const items = await itemManager.list();
    expect(items.data.length).toBe(1);
  }

  for (let i = 0 ; i < 5 ; i++) {
    const meta2 = {
      type: "ITEMTYPE",
      someval: "someval",
      i,
    };
    const content2 = Uint8Array.from([i, 7, 2, 3, 5]);
    const item2 = await itemManager.create(meta2, content2);
    items.push(item2);
  }

  await itemManager.batch(items);

  {
    const meta3 = { ...meta, someval: "some2" };
    const item2 = item._clone();

    item2.setMeta(meta3);
    await itemManager.batch([item2]);

    meta3.someval = "some3";
    item.setMeta(meta3);

    // Old stoken in the item itself should work for batch and fail for transaction or batch with deps
    await expect(itemManager.transaction([item])).rejects.toBeInstanceOf(Etebase.ConflictError);
    await expect(itemManager.batch([item], [item])).rejects.toBeInstanceOf(Etebase.ConflictError);
    await itemManager.batch([item]);
  }

  {
    // Global stoken test
    const meta3 = { ...meta, someval: "some2" };
    item.setMeta(meta3);

    const newCol = await collectionManager.fetch(col.uid);
    const stoken = newCol.stoken;
    const badEtag = col.etag;

    await expect(itemManager.batch([item], null, { stoken: badEtag })).rejects.toBeInstanceOf(Etebase.ConflictError);

    await itemManager.batch([item], null, { stoken });
  }
});

it("Item fetch updates", async () => {
  const collectionManager = etebase.getCollectionManager();
  const colMeta: Etebase.ItemMetadata = {
    name: "Calendar",
    description: "Mine",
    color: "#ffffff",
  };

  const colContent = Uint8Array.from([1, 2, 3, 5]);
  const col = await collectionManager.create(colType, colMeta, colContent);

  await collectionManager.upload(col);

  {
    const collections = await collectionManager.list(colType);
    expect(collections.data.length).toBe(1);
  }

  const itemManager = collectionManager.getItemManager(col);

  const meta: Etebase.ItemMetadata = {
    type: "ITEMTYPE",
  };
  const content = Uint8Array.from([1, 2, 3, 6]);

  const item = await itemManager.create(meta, content);

  await itemManager.batch([item]);

  const items: Etebase.Item[] = [];

  {
    const items = await itemManager.list();
    expect(items.data.length).toBe(1);
  }

  for (let i = 0 ; i < 5 ; i++) {
    const meta2 = {
      type: "ITEMTYPE",
      someval: "someval",
      i,
    };
    const content2 = Uint8Array.from([i, 7, 2, 3, 5]);
    const item2 = await itemManager.create(meta2, content2);
    items.push(item2);
  }

  await itemManager.batch(items);

  {
    const items = await itemManager.list();
    expect(items.data.length).toBe(6);
  }

  // Fetch multi
  {
    let items2 = await itemManager.fetchMulti(items.map((x) => x.uid));
    expect(items2.data.length).toBe(5);

    items2 = await itemManager.fetchMulti(["L4QQdlkCDJ9ySmrGD5fM0DsFo08MnWel", items[0].uid]);
    // Only 1 because only one of the items exists
    expect(items2.data.length).toBe(1);
  }


  let stoken: string | null = null;

  {
    const newCol = await collectionManager.fetch(col.uid);
    stoken = newCol.stoken;
  }

  {
    let updates = await itemManager.fetchUpdates(items);
    expect(updates.data.length).toBe(0);

    updates = await itemManager.fetchUpdates(items, { stoken });
    expect(updates.data.length).toBe(0);
  }

  {
    const meta3 = { ...meta, someval: "some2" };
    const item2 = items[0]._clone();

    item2.setMeta(meta3);
    await itemManager.batch([item2]);
  }

  {
    let updates = await itemManager.fetchUpdates(items);
    expect(updates.data.length).toBe(1);

    updates = await itemManager.fetchUpdates(items, { stoken });
    expect(updates.data.length).toBe(1);
  }

  {
    const item2 = await itemManager.fetch(items[0].uid);
    let updates = await itemManager.fetchUpdates([item2]);
    expect(updates.data.length).toBe(0);

    updates = await itemManager.fetchUpdates([item2], { stoken });
    expect(updates.data.length).toBe(1);
  }

  {
    const newCol = await collectionManager.fetch(col.uid);
    stoken = newCol.stoken;
  }

  {
    const updates = await itemManager.fetchUpdates(items, { stoken });
    expect(updates.data.length).toBe(0);
  }
});

it("Item revisions", async () => {
  const collectionManager = etebase.getCollectionManager();
  const colMeta: Etebase.ItemMetadata = {
    name: "Calendar",
    description: "Mine",
    color: "#ffffff",
  };

  const col = await collectionManager.create(colType, colMeta, "");
  await collectionManager.upload(col);


  const itemManager = collectionManager.getItemManager(col);

  const meta: Etebase.ItemMetadata = {
    type: "ITEMTYPE",
  };

  const item = await itemManager.create(meta, "");

  for (let i = 0 ; i < 5 ; i++) {
    const content = Uint8Array.from([1, 2, i]);
    await item.setContent(content);

    await itemManager.batch([item]);
  }

  await item.setContent("Latest");
  await itemManager.batch([item]);

  {
    let revisions = await itemManager.itemRevisions(item, { iterator: item.etag });
    expect(revisions.data.length).toBe(5);
    expect(revisions.done).toBeTruthy();
    revisions = await itemManager.itemRevisions(item, { iterator: item.etag, limit: 5 });
    expect(revisions.done).toBeTruthy();

    for (let i = 0 ; i < 5 ; i++) {
      const content = Uint8Array.from([1, 2, i]);
      // The revisions are ordered newest to oldest
      const rev = revisions.data[4 - i];

      expect(await rev.getContent()).toEqual(content);
    }
  }

  // Iterate through revisions
  {
    let iterator: string | null = item.etag;
    for (let i = 0 ; i < 2 ; i++) {
      const revisions = await itemManager.itemRevisions(item, { limit: 2, iterator });
      expect(revisions.done).toBe(i === 2);
      iterator = revisions.iterator as string;
    }
  }
});


it("Collection invitations", async () => {
  const collectionManager = etebase.getCollectionManager();
  const colMeta: Etebase.ItemMetadata = {
    name: "Calendar",
    description: "Mine",
    color: "#ffffff",
  };

  const colContent = Uint8Array.from([1, 2, 3, 5]);
  const col = await collectionManager.create(colType, colMeta, colContent);

  await collectionManager.upload(col);

  {
    const collections = await collectionManager.list(colType);
    expect(collections.data.length).toBe(1);
  }

  const itemManager = collectionManager.getItemManager(col);

  const items: Etebase.Item[] = [];

  for (let i = 0 ; i < 5 ; i++) {
    const meta2 = {
      type: "ITEMTYPE",
      someval: "someval",
      i,
    };
    const content2 = Uint8Array.from([i, 7, 2, 3, 5]);
    const item2 = await itemManager.create(meta2, content2);
    items.push(item2);
  }

  await itemManager.batch(items);

  const collectionInvitationManager = etebase.getInvitationManager();

  const etebase2 = await prepareUserForTest(USER2);
  const collectionManager2 = etebase2.getCollectionManager();
  const collectionInvitationManager2 = etebase2.getInvitationManager();

  const user2Profile = await collectionInvitationManager.fetchUserProfile(USER2.username);

  // Should be verified by user1 off-band
  const user2pubkey = collectionInvitationManager2.pubkey;
  expect(user2Profile.pubkey).toEqual(user2pubkey);
  // Off-band verification:
  expect(Etebase.getPrettyFingerprint(user2Profile.pubkey)).toEqual(Etebase.getPrettyFingerprint(user2pubkey));

  await collectionInvitationManager.invite(col, USER2.username, user2Profile.pubkey, Etebase.CollectionAccessLevel.ReadWrite);

  let invitations = await collectionInvitationManager2.listIncoming();
  expect(invitations.data.length).toBe(1);
  expect(invitations.data[0].fromUsername).toEqual(USER.username);

  await collectionInvitationManager2.reject(invitations.data[0]);

  {
    const collections = await collectionManager2.list(colType);
    expect(collections.data.length).toBe(0);
  }

  {
    const invitations = await collectionInvitationManager2.listIncoming();
    expect(invitations.data.length).toBe(0);
  }

  // Invite and then disinvite
  await collectionInvitationManager.invite(col, USER2.username, user2Profile.pubkey, Etebase.CollectionAccessLevel.ReadWrite);

  invitations = await collectionInvitationManager2.listIncoming();
  expect(invitations.data.length).toBe(1);

  await collectionInvitationManager.disinvite(invitations.data[0]);

  {
    const collections = await collectionManager2.list(colType);
    expect(collections.data.length).toBe(0);
  }

  {
    const invitations = await collectionInvitationManager2.listIncoming();
    expect(invitations.data.length).toBe(0);
  }


  // Invite again, this time accept
  await collectionInvitationManager.invite(col, USER2.username, user2Profile.pubkey, Etebase.CollectionAccessLevel.ReadWrite);

  invitations = await collectionInvitationManager2.listIncoming();
  expect(invitations.data.length).toBe(1);

  let stoken: string | null;
  {
    const newCol = await collectionManager.fetch(col.uid);
    stoken = newCol.stoken;
  }

  // Should be verified by user2 off-band
  const user1pubkey = collectionInvitationManager.pubkey;
  expect(invitations.data[0].fromPubkey).toEqual(user1pubkey);

  await collectionInvitationManager2.accept(invitations.data[0]);

  {
    const collections = await collectionManager2.list(colType);
    expect(collections.data.length).toBe(1);

    collections.data[0].getMeta();
    expect(collections.data[0].getCollectionType()).toEqual(colType);
  }

  {
    const invitations = await collectionInvitationManager2.listIncoming();
    expect(invitations.data.length).toBe(0);
  }

  const col2 = await collectionManager2.fetch(col.uid);
  const collectionMemberManager2 = collectionManager2.getMemberManager(col2);

  await collectionMemberManager2.leave();

  {
    const collections = await collectionManager2.list(colType, { stoken });
    expect(collections.data.length).toBe(0);
    expect(collections.removedMemberships?.length).toBe(1);
  }

  // Add again
  await collectionInvitationManager.invite(col, USER2.username, user2Profile.pubkey, Etebase.CollectionAccessLevel.ReadWrite);

  invitations = await collectionInvitationManager2.listIncoming();
  expect(invitations.data.length).toBe(1);
  await collectionInvitationManager2.accept(invitations.data[0]);

  {
    const newCol = await collectionManager.fetch(col.uid);
    expect(stoken).not.toEqual(newCol.stoken);

    const collections = await collectionManager2.list(colType, { stoken });
    expect(collections.data.length).toBe(1);
    expect(collections.data[0].uid).toEqual(col.uid);
    expect(collections.removedMemberships).not.toBeDefined();
  }

  // Remove
  {
    const newCol = await collectionManager.fetch(col.uid);
    expect(stoken).not.toEqual(newCol.stoken);

    const collectionMemberManager = collectionManager.getMemberManager(col);
    await collectionMemberManager.remove(USER2.username);

    const collections = await collectionManager2.list(colType, { stoken });
    expect(collections.data.length).toBe(0);
    expect(collections.removedMemberships?.length).toBe(1);

    stoken = newCol.stoken;
  }

  {
    const collections = await collectionManager2.list(colType, { stoken });
    expect(collections.data.length).toBe(0);
    expect(collections.removedMemberships?.length).toBe(1);
  }

  await etebase2.logout();
}, 10000);

it("Iterating invitations", async () => {
  const etebase2 = await prepareUserForTest(USER2);
  const collectionManager = etebase.getCollectionManager();

  const collectionInvitationManager = etebase.getInvitationManager();
  const user2Profile = await collectionInvitationManager.fetchUserProfile(USER2.username);

  const collections = [];

  for (let i = 0 ; i < 3 ; i++) {
    const colMeta: Etebase.ItemMetadata = {
      name: `Calendar ${i}`,
    };

    const col = await collectionManager.create(colType, colMeta, "");

    await collectionManager.upload(col);
    await collectionInvitationManager.invite(col, USER2.username, user2Profile.pubkey, Etebase.CollectionAccessLevel.ReadWrite);

    collections.push(col);
  }

  const collectionInvitationManager2 = etebase2.getInvitationManager();

  // Check incoming
  {
    const invitations = await collectionInvitationManager2.listIncoming();
    expect(invitations.data.length).toBe(3);
  }

  {
    let iterator: string | null = null;
    for (let i = 0 ; i < 2 ; i++) {
      const invitations = await collectionInvitationManager2.listIncoming({ limit: 2, iterator });
      expect(invitations.done).toBe(i === 1);
      iterator = invitations.iterator as string;
    }
  }

  // Check outgoing
  {
    const invitations = await collectionInvitationManager.listOutgoing();
    expect(invitations.data.length).toBe(3);
  }

  {
    let iterator: string | null = null;
    for (let i = 0 ; i < 2 ; i++) {
      const invitations = await collectionInvitationManager.listOutgoing({ limit: 2, iterator });
      expect(invitations.done).toBe(i === 1);
      iterator = invitations.iterator as string;
    }
  }

  await etebase2.logout();
});

it("Collection access level", async () => {
  const collectionManager = etebase.getCollectionManager();
  const colMeta: Etebase.ItemMetadata = {
    name: "Calendar",
    description: "Mine",
    color: "#ffffff",
  };

  const colContent = Uint8Array.from([1, 2, 3, 5]);
  const col = await collectionManager.create(colType, colMeta, colContent);

  await collectionManager.upload(col);

  {
    const collections = await collectionManager.list(colType);
    expect(collections.data.length).toBe(1);
  }

  const itemManager = collectionManager.getItemManager(col);

  const items: Etebase.Item[] = [];

  for (let i = 0 ; i < 5 ; i++) {
    const meta2 = {
      type: "ITEMTYPE",
      someval: "someval",
      i,
    };
    const content2 = Uint8Array.from([i, 7, 2, 3, 5]);
    const item2 = await itemManager.create(meta2, content2);
    items.push(item2);
  }

  await itemManager.batch(items);

  const collectionMemberManager = collectionManager.getMemberManager(col);
  const collectionInvitationManager = etebase.getInvitationManager();

  const etebase2 = await prepareUserForTest(USER2);
  const collectionManager2 = etebase2.getCollectionManager();

  const user2Profile = await collectionInvitationManager.fetchUserProfile(USER2.username);


  await collectionInvitationManager.invite(col, USER2.username, user2Profile.pubkey, Etebase.CollectionAccessLevel.ReadWrite);

  const collectionInvitationManager2 = etebase2.getInvitationManager();

  const invitations = await collectionInvitationManager2.listIncoming();
  expect(invitations.data.length).toBe(1);

  await collectionInvitationManager2.accept(invitations.data[0]);


  const col2 = await collectionManager2.fetch(col.uid);
  const itemManager2 = collectionManager2.getItemManager(col2);

  // Item creation: success
  {
    const members = await collectionMemberManager.list();
    expect(members.data.length).toBe(2);
    for (const member of members.data) {
      if (member.username === USER2.username) {
        expect(member.accessLevel).toBe(Etebase.CollectionAccessLevel.ReadWrite);
      }
    }

    const meta: Etebase.ItemMetadata = {
      type: "ITEMTYPE2",
    };
    const content = Uint8Array.from([1, 2, 3, 6]);

    const item = await itemManager2.create(meta, content);
    await itemManager2.batch([item]);
  }

  await collectionMemberManager.modifyAccessLevel(USER2.username, Etebase.CollectionAccessLevel.ReadOnly);

  // Item creation: fail
  {
    const members = await collectionMemberManager.list();
    expect(members.data.length).toBe(2);
    for (const member of members.data) {
      if (member.username === USER2.username) {
        expect(member.accessLevel).toBe(Etebase.CollectionAccessLevel.ReadOnly);
      }
    }

    const meta: Etebase.ItemMetadata = {
      type: "ITEMTYPE3",
    };
    const content = Uint8Array.from([1, 2, 3, 6]);

    const item = await itemManager2.create(meta, content);
    await expect(itemManager2.batch([item])).rejects.toBeInstanceOf(Etebase.PermissionDeniedError);
  }

  await collectionMemberManager.modifyAccessLevel(USER2.username, Etebase.CollectionAccessLevel.Admin);

  // Item creation: success
  {
    const members = await collectionMemberManager.list();
    expect(members.data.length).toBe(2);
    for (const member of members.data) {
      if (member.username === USER2.username) {
        expect(member.accessLevel).toBe(Etebase.CollectionAccessLevel.Admin);
      }
    }

    const meta: Etebase.ItemMetadata = {
      type: "ITEMTYPE3",
    };
    const content = Uint8Array.from([1, 2, 3, 6]);

    const item = await itemManager2.create(meta, content);
    await itemManager2.batch([item]);
  }

  // Iterate members
  {
    const members = await collectionMemberManager.list({ limit: 1 });
    expect(members.data.length).toBe(1);
    const members2 = await collectionMemberManager.list({ limit: 1, iterator: members.iterator });
    expect(members2.data.length).toBe(1);
    // Verify we got two different usersnames
    expect(members.data[0].username).not.toEqual(members2.data[0].username);

    const membersDone = await collectionMemberManager.list();
    expect(membersDone.done).toBeTruthy();
  }

  await etebase2.logout();
});

it("Session store and restore", async () => {
  const collectionManager = etebase.getCollectionManager();
  const meta: Etebase.ItemMetadata = {
    name: "Calendar",
  };

  const col = await collectionManager.create(colType, meta, "test");
  await collectionManager.upload(col);

  // Verify we can store and restore without an encryption key
  {
    const saved = await etebase.save();
    const etebase2 = await Etebase.Account.restore(saved);

    // Verify we can access the data
    const collectionManager2 = etebase2.getCollectionManager();
    const collections = await collectionManager2.list(colType);
    expect(collections.data.length).toBe(1);
    expect(await collections.data[0].getContent(Etebase.OutputFormat.String)).toEqual("test");
  }

  // Verify we can store and restore with an encryption key
  {
    const encryptionKey = Etebase.randomBytes(32);
    const saved = await etebase.save(encryptionKey);
    // Fail without an encryption key
    // FIXME: Test for the correct error value
    await expect(Etebase.Account.restore(saved)).rejects.toBeTruthy();
    const etebase2 = await Etebase.Account.restore(saved, encryptionKey);

    // Verify we can access the data
    const collectionManager2 = etebase2.getCollectionManager();
    const collections = await collectionManager2.list(colType);
    expect(collections.data.length).toBe(1);
    expect(await collections.data[0].getContent(Etebase.OutputFormat.String)).toEqual("test");
  }
});

it("Cache collections and items", async () => {
  const collectionManager = etebase.getCollectionManager();
  const colMeta: Etebase.ItemMetadata = {
    name: "Calendar",
  };

  const col = await collectionManager.create(colType, colMeta, "test");
  await collectionManager.upload(col);

  const itemManager = collectionManager.getItemManager(col);

  const meta: Etebase.ItemMetadata = {
    type: "ITEMTYPE",
  };
  const content = Uint8Array.from([1, 2, 3, 6]);

  const item = await itemManager.create(meta, content);
  await itemManager.batch([item]);

  const optionsArray = [
    { saveContent: true },
    { saveContent: false },
  ];
  for (const options of optionsArray) {
    const savedCachedCollection = collectionManager.cacheSave(col, options);
    const cachedCollection = collectionManager.cacheLoad(savedCachedCollection);

    expect(col.uid).toEqual(cachedCollection.uid);
    expect(col.etag).toEqual(cachedCollection.etag);
    expect(col.getMeta()).toEqual(cachedCollection.getMeta());


    const savedCachedItem = itemManager.cacheSave(item, options);
    const cachedItem = itemManager.cacheLoad(savedCachedItem);

    expect(item.uid).toEqual(cachedItem.uid);
    expect(item.etag).toEqual(cachedItem.etag);
    expect(item.getMeta()).toEqual(cachedItem.getMeta());
  }

  // Verify content
  {
    const options = { saveContent: true };
    const savedCachedItem = itemManager.cacheSave(item, options);
    const cachedItem = itemManager.cacheLoad(savedCachedItem);

    expect(await item.getContent()).toEqual(await cachedItem.getContent());
  }
});

it("Chunk pre-upload and download-missing", async () => {
  const collectionManager = etebase.getCollectionManager();
  const colMeta: Etebase.ItemMetadata = {
    name: "Calendar",
  };

  const col = await collectionManager.create(colType, colMeta, "");
  await collectionManager.upload(col);

  const itemManager = collectionManager.getItemManager(col);
  const meta: Etebase.ItemMetadata = {
    type: "itemtype",
  };
  const content = "Something";
  const item = await itemManager.create(meta, content);
  expect(item.isMissingContent).not.toBeTruthy();
  await itemManager.uploadContent(item);
  // Verify we don't fail even when already uploaded
  await itemManager.uploadContent(item);
  await itemManager.batch([item]);

  {
    const item2 = await itemManager.fetch(item.uid, { prefetch: PrefetchOption.Medium });
    const meta2 = item2.getMeta();
    expect(meta2).toEqual(meta);
    // We can't get the content of partial item
    await expect(item2.getContent()).rejects.toBeInstanceOf(Etebase.MissingContentError);
    expect(item2.isMissingContent).toBeTruthy();
    // Fetch the content and then try to get it
    await itemManager.downloadContent(item2);
    expect(item2.isMissingContent).not.toBeTruthy();
    expect(await item2.getContent(Etebase.OutputFormat.String)).toEqual(content);
  }
});

it("Chunking large data", async () => {
  const collectionManager = etebase.getCollectionManager();
  const colMeta: Etebase.ItemMetadata = {
    name: "Calendar",
  };

  const buf = randomBytesDeterministic(120 * 1024, new Uint8Array(32)); // 120kb of psuedorandom data
  const col = await collectionManager.create(colType, colMeta, "");
  const itemManager = collectionManager.getItemManager(col);
  const item = await itemManager.create({}, buf);
  await verifyItem(item, {}, buf);

  async function itemGetChunkUids(it: Etebase.Item): Promise<string[]> {
    // XXX: hack - get the chunk uids from the cached saving
    const cachedItem = msgpackDecode(itemManager.cacheSave(it, { saveContent: false })) as any[];
    const cachedRevision = (msgpackDecode(cachedItem[cachedItem.length - 1]) as any[]);
    const cachedChunks = cachedRevision[cachedRevision.length - 1] as [Uint8Array][];
    return cachedChunks.map((x) => toBase64(x[0]));
  }

  const uidSet = new Set<string>();

  // Get the first chunks and init uidSet
  {
    const chunkUids = await itemGetChunkUids(item);
    expect(chunkUids.length).toEqual(8);

    chunkUids.forEach((x) => uidSet.add(x));
  }

  // Bite a chunk off the new buffer
  const biteStart = 10000;
  const biteSize = 210;
  const newBuf = new Uint8Array(buf.length - biteSize);
  newBuf.set(buf.subarray(0, biteStart));
  newBuf.set(buf.subarray(biteStart + biteSize), biteStart);

  newBuf[39000] = 0;
  newBuf[39001] = 1;
  newBuf[39002] = 2;
  newBuf[39003] = 3;
  newBuf[39004] = 4;

  await item.setContent(newBuf);
  await verifyItem(item, {}, newBuf);

  // Verify how much has changed
  {
    const chunkUids = await itemGetChunkUids(item);
    expect(chunkUids.length).toEqual(8);

    let reused = 0;

    chunkUids.forEach((x) => {
      if (uidSet.has(x)) {
        reused++;
      }
    });

    expect(reused).toEqual(5);
  }
});

it.skip("Login and password change", async () => {
  const anotherPassword = "AnotherPassword";
  const etebase2 = await Etebase.Account.login(USER2.username, USER2.password, testApiBase);

  const collectionManager2 = etebase2.getCollectionManager();
  const colMeta: Etebase.ItemMetadata = {
    name: "Calendar",
    description: "Mine",
    color: "#ffffff",
  };

  const colContent = Uint8Array.from([1, 2, 3, 5]);
  const col = await collectionManager2.create(colType, colMeta, colContent);

  await collectionManager2.upload(col);

  await etebase2.changePassword(anotherPassword);

  {
    // Verify we can still access the data
    const collections = await collectionManager2.list(colType);
    expect(colMeta).toEqual(collections.data[0].getMeta());
  }

  await etebase2.logout();

  await expect(Etebase.Account.login(USER2.username, USER2.password, testApiBase)).rejects.toBeInstanceOf(Etebase.UnauthorizedError);

  const etebase3 = await Etebase.Account.login(USER2.username, anotherPassword, testApiBase);

  const collectionManager3 = etebase3.getCollectionManager();

  {
    // Verify we can still access the data
    const collections = await collectionManager3.list(colType);
    expect(colMeta).toEqual(collections.data[0].getMeta());
  }

  await etebase3.changePassword(USER2.password);

  await etebase3.logout();
}, 30000);
