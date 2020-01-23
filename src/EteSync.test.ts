import 'whatwg-fetch';

import * as EteSync from './EteSync';

import sjcl from 'sjcl';

import { USER, PASSWORD, keyBase64 } from './TestConstants';

const testApiBase = 'http://localhost:8000';

sjcl.random.addEntropy('seedForTheTests', 1024, 'FakeSeed');


let credentials: EteSync.Credentials;

beforeEach(async () => {
  const authenticator = new EteSync.Authenticator(testApiBase);
  const authToken = await authenticator.getAuthToken(USER, PASSWORD);

  credentials = new EteSync.Credentials(USER, authToken);

  await fetch(testApiBase + '/reset/', {
    method: 'post',
    headers: { Authorization: 'Token ' + credentials.authToken },
  });
});

afterEach(async () => {
  const authenticator = new EteSync.Authenticator(testApiBase);
  await authenticator.invalidateToken(credentials.authToken);
});

it('Simple sync', async () => {
  const journalManager = new EteSync.JournalManager(credentials, testApiBase);
  let journals = await journalManager.list();
  expect(journals.length).toBe(0);

  const uid1 = sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash('id1'));
  const cryptoManager = new EteSync.CryptoManager(keyBase64, USER);
  const info1 = new EteSync.CollectionInfo({ uid: uid1, content: 'test', displayName: 'Dislpay 1' });
  const journal = new EteSync.Journal();
  journal.setInfo(cryptoManager, info1);

  await expect(journalManager.create(journal)).resolves.toBeDefined();

  // Uid clash
  await expect(journalManager.create(journal)).rejects.toBeInstanceOf(EteSync.HTTPError);

  journals = await journalManager.list();
  expect(journals.length).toBe(1);
  expect(journals[0].uid).toBe(journal.uid);

  // Update
  const info2 = new EteSync.CollectionInfo(info1);
  info2.displayName = 'Display 2';

  journal.setInfo(cryptoManager, info2);
  await expect(journalManager.update(journal)).resolves.toBeDefined();

  journals = await journalManager.list();
  expect(journals.length).toBe(1);

  expect(journals[0].getInfo(cryptoManager).displayName).toBe(info2.displayName);

  // Delete
  await expect(journalManager.delete(journal)).resolves.toBeDefined();
  journals = await journalManager.list();
  expect(journals.length).toBe(0);
});

it('Journal Entry sync', async () => {
  const journalManager = new EteSync.JournalManager(credentials, testApiBase);

  const uid1 = sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash('id1'));
  const cryptoManager = new EteSync.CryptoManager(keyBase64, USER);
  const info1 = new EteSync.CollectionInfo({ uid: uid1, content: 'test', displayName: 'Dislpay 1' });
  const journal = new EteSync.Journal();
  journal.setInfo(cryptoManager, info1);

  await expect(journalManager.create(journal)).resolves.toBeDefined();

  const entryManager = new EteSync.EntryManager(credentials, testApiBase, journal.uid);

  {
    const entries = await entryManager.list(null);
    expect(entries.length).toBe(0);
  }

  const syncEntry = new EteSync.SyncEntry({ action: 'ADD', content: 'bla' });
  let prevUid = null;
  const entry = new EteSync.Entry();
  entry.setSyncEntry(cryptoManager, syncEntry, prevUid);

  await expect(entryManager.create([entry], prevUid)).resolves.toBeDefined();
  prevUid = entry.uid;

  {
    // Verify we get back what we sent
    const entries = await entryManager.list(null);
    expect(entries[0].serialize()).toEqual(entry.serialize());
    syncEntry.uid = entries[0].uid;
    expect(entries[0].getSyncEntry(cryptoManager, null)).toEqual(syncEntry);
  }

  let entry2 = new EteSync.Entry();
  entry2.setSyncEntry(cryptoManager, syncEntry, prevUid);

  {
    // Try to push good entries with a bad prevUid
    const entries = [entry2];
    await expect(entryManager.create(entries, null)).rejects.toBeInstanceOf(EteSync.HTTPError);

    // Second try with good prevUid
    await expect(entryManager.create(entries, prevUid)).resolves.toBeDefined();
    prevUid = entry2.uid;
  }

  {
    // Check last works:
    let entries = await entryManager.list(null);
    expect(entries.length).toBe(2);

    entries = await entryManager.list(entry.uid);
    expect(entries.length).toBe(1);

    entries = await entryManager.list(entry2.uid);
    expect(entries.length).toBe(0);
  }

  {
    // Corrupt the journal and verify we get it:
    entry2 = new EteSync.Entry();
    entry2.setSyncEntry(cryptoManager, syncEntry, 'somebaduid');
    await expect(entryManager.create([entry2], prevUid)).resolves.toBeDefined();

    const entries = await entryManager.list(null);

    expect(() => {
      let prev = null;
      for (const ent of entries) {
        expect(ent.getSyncEntry(cryptoManager, prev)).toBeDefined();
        prev = ent.uid;
      }
    }).toThrowError();
  }
});

it('User info sync', async () => {
  const cryptoManager = new EteSync.CryptoManager(keyBase64, 'userInfo');
  const userInfoManager = new EteSync.UserInfoManager(credentials, testApiBase);

  // Get when there's nothing
  await expect(userInfoManager.fetch(USER)).rejects.toBeInstanceOf(EteSync.HTTPError);

  // Create
  const userInfo = new EteSync.UserInfo(USER);
  userInfo.setKeyPair(cryptoManager, new EteSync.AsymmetricKeyPair([0, 1, 2, 3], [4, 5, 6, 6]));
  await expect(userInfoManager.create(userInfo)).resolves.not.toBeNull();

  // Get
  let userInfo2 = await userInfoManager.fetch(USER);
  expect(userInfo2).not.toBeNull();
  expect(userInfo.getKeyPair(cryptoManager)).toEqual(userInfo2!.getKeyPair(cryptoManager));

  // Update
  userInfo.setKeyPair(cryptoManager, new EteSync.AsymmetricKeyPair([1, 94, 45], [4, 34, 45, 45]));
  await userInfoManager.update(userInfo);
  userInfo2 = await userInfoManager.fetch(USER);
  expect(userInfo2).not.toBeNull();
  expect(userInfo.getKeyPair(cryptoManager)).toEqual(userInfo2!.getKeyPair(cryptoManager));

  // Delete
  await userInfoManager.delete(userInfo);
  await expect(userInfoManager.fetch(USER)).rejects.toBeInstanceOf(EteSync.HTTPError);
});
