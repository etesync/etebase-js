import URI from 'urijs';

import * as Constants from './Constants';

import { deriveKey, sodium, concatArrayBuffers, AsymmetricCryptoManager } from './Crypto';
export { deriveKey, ready } from './Crypto';
export * from './Exceptions';
import { base62, base64, fromBase64, toBase64 } from './Helpers';
export { base62, base64, fromBase64, toBase64 } from './Helpers';

import {
  CollectionAccessLevel,
  CollectionCryptoManager,
  CollectionMetadata,
  CollectionItemMetadata,
  EncryptedCollection,
  EncryptedCollectionItem,
  getMainCryptoManager,
  SignedInvitationRead,
} from './EncryptedModels';
export * from './EncryptedModels'; // FIXME: cherry-pick what we export
import {
  Authenticator,
  CollectionManagerOnline,
  CollectionItemManagerOnline,
  CollectionInvitationManagerOnline,
  CollectionMemberManagerOnline,
  FetchOptions,
  ItemFetchOptions,
  LoginResponseUser,
  User,
  UserProfile,
} from './OnlineManagers';
export { User, FetchOptions, ItemFetchOptions } from './OnlineManagers';

export { CURRENT_VERSION } from './Constants';

export interface AccountData {
  version: number;
  key: base64;
  user: LoginResponseUser;
  serverUrl: string;
  authToken?: string;
}

export class Account {
  private static readonly CURRENT_VERSION = 1;

  private mainKey: Uint8Array;
  private version: number;
  public user: LoginResponseUser;
  public serverUrl: string;
  public authToken: string | null;

  private constructor(mainEncryptionKey: Uint8Array, version: number) {
    this.mainKey = mainEncryptionKey;
    this.version = version;
    this.authToken = null;
  }

  public static async signup(user: User, password: string, serverUrl?: string) {
    serverUrl = serverUrl ?? Constants.SERVER_URL;
    const authenticator = new Authenticator(serverUrl);
    const version = this.CURRENT_VERSION;
    const salt = sodium.randombytes_buf(32);

    const mainKey = deriveKey(salt, password);
    const mainCryptoManager = getMainCryptoManager(mainKey, version);
    const loginCryptoManager = mainCryptoManager.getLoginCryptoManager();

    const identityCryptoManager = AsymmetricCryptoManager.keygen();

    const accountKey = sodium.crypto_aead_chacha20poly1305_ietf_keygen();
    const encryptedContent = mainCryptoManager.encrypt(concatArrayBuffers(accountKey, identityCryptoManager.privkey));

    const loginResponse = await authenticator.signup(user, salt, loginCryptoManager.pubkey, identityCryptoManager.pubkey, encryptedContent);

    const ret = new this(mainKey, version);

    ret.user = loginResponse.user;
    ret.authToken = loginResponse.token;
    ret.serverUrl = serverUrl;

    return ret;
  }

  public static async login(username: string, password: string, serverUrl?: string) {
    serverUrl = serverUrl ?? Constants.SERVER_URL;
    const authenticator = new Authenticator(serverUrl);
    const loginChallenge = await authenticator.getLoginChallenge(username);

    const mainKey = deriveKey(fromBase64(loginChallenge.salt), password);
    const mainCryptoManager = getMainCryptoManager(mainKey, loginChallenge.version);
    const loginCryptoManager = mainCryptoManager.getLoginCryptoManager();

    const response = JSON.stringify({
      username,
      challenge: loginChallenge.challenge,
      host: URI(serverUrl).host(),
    });

    const loginResponse = await authenticator.login(response, loginCryptoManager.signDetached(sodium.from_string(response)));

    const ret = new this(mainKey, loginChallenge.version);

    ret.user = loginResponse.user;
    ret.authToken = loginResponse.token;
    ret.serverUrl = serverUrl;

    return ret;
  }

  public async fetchToken() {
    const serverUrl = this.serverUrl;
    const authenticator = new Authenticator(serverUrl);
    const username = this.user.username;
    const loginChallenge = await authenticator.getLoginChallenge(username);

    const mainKey = this.mainKey;
    const mainCryptoManager = getMainCryptoManager(mainKey, loginChallenge.version);
    const loginCryptoManager = mainCryptoManager.getLoginCryptoManager();

    const response = JSON.stringify({
      username,
      challenge: loginChallenge.challenge,
      host: URI(serverUrl).host(),
    });

    const loginResponse = await authenticator.login(response, loginCryptoManager.signDetached(sodium.from_string(response)));

    this.authToken = loginResponse.token;
  }

  public async logout() {
    const authenticator = new Authenticator(this.serverUrl);

    authenticator.logout(this.authToken!);
    this.version = -1;
    this.mainKey = new Uint8Array();
    this.authToken = null;
  }

  public async changePassword(password: string) {
    const authenticator = new Authenticator(this.serverUrl);
    const username = this.user.username;
    const loginChallenge = await authenticator.getLoginChallenge(username);

    const oldMainCryptoManager = getMainCryptoManager(this.mainKey, this.version);
    const content = oldMainCryptoManager.decrypt(fromBase64(this.user.encryptedContent));

    const mainKey = deriveKey(fromBase64(loginChallenge.salt), password);
    const mainCryptoManager = getMainCryptoManager(mainKey, this.version);
    const loginCryptoManager = mainCryptoManager.getLoginCryptoManager();

    const encryptedContent = mainCryptoManager.encrypt(content);

    await authenticator.changePassword(this.authToken!, loginCryptoManager.pubkey, encryptedContent);

    this.mainKey = mainKey;
    this.user.encryptedContent = toBase64(encryptedContent);
  }

  public save(): AccountData {
    const ret: AccountData = {
      user: this.user,
      authToken: this.authToken!!,
      serverUrl: this.serverUrl,
      version: this.version,
      key: toBase64(this.mainKey),
    };

    return ret;
  }

  public static load(accountData: AccountData) {
    const ret = new this(fromBase64(accountData.key), accountData.version);
    ret.user = accountData.user;
    ret.authToken = accountData.authToken ?? null;
    ret.serverUrl = accountData.serverUrl;

    return ret;
  }

  public getCollectionManager() {
    return new CollectionManager(this);
  }

  public getCryptoManager() {
    // FIXME: cache this
    const mainCryptoManager = getMainCryptoManager(this.mainKey, this.version);
    const content = mainCryptoManager.decrypt(fromBase64(this.user.encryptedContent));
    return mainCryptoManager.getAccountCryptoManager(content.subarray(0, sodium.crypto_aead_chacha20poly1305_ietf_KEYBYTES));
  }

  public getIdentityCryptoManager() {
    // FIXME: cache this
    const mainCryptoManager = getMainCryptoManager(this.mainKey, this.version);
    const content = mainCryptoManager.decrypt(fromBase64(this.user.encryptedContent));
    return mainCryptoManager.getIdentityCryptoManager(content.subarray(sodium.crypto_aead_chacha20poly1305_ietf_KEYBYTES));
  }
}

export class CollectionManager {
  private readonly etesync: Account;
  private readonly onlineManager: CollectionManagerOnline;

  constructor(etesync: Account) {
    this.etesync = etesync;
    this.onlineManager = new CollectionManagerOnline(this.etesync);
  }

  public async create(meta: CollectionMetadata, content: Uint8Array): Promise<Collection> {
    const mainCryptoManager = this.etesync.getCryptoManager();
    const encryptedCollection = await EncryptedCollection.create(mainCryptoManager, meta, content);
    return new Collection(encryptedCollection.getCryptoManager(mainCryptoManager), encryptedCollection);
  }

  public async fetch(colUid: base62, options: FetchOptions) {
    const mainCryptoManager = this.etesync.getCryptoManager();
    const encryptedCollection = await this.onlineManager.fetch(colUid, options);
    return new Collection(encryptedCollection.getCryptoManager(mainCryptoManager), encryptedCollection);
  }

  public async list(options: FetchOptions) {
    const mainCryptoManager = this.etesync.getCryptoManager();
    const ret = await this.onlineManager.list(options);
    return {
      ...ret,
      data: ret.data.map((x) => new Collection(x.getCryptoManager(mainCryptoManager), x)),
    };
  }

  public async upload(collection: Collection, options?: FetchOptions) {
    const col = collection.encryptedCollection;
    // If we have a etag, it means we previously fetched it.
    if (col.etag) {
      await this.onlineManager.update(col, options);
    } else {
      await this.onlineManager.create(col, options);
    }
    col.__markSaved();
  }

  public async transaction(collection: Collection, options?: FetchOptions) {
    const col = collection.encryptedCollection;
    // If we have a etag, it means we previously fetched it.
    if (col.etag) {
      await this.onlineManager.update(col, { ...options, stoken: col.stoken });
    } else {
      await this.onlineManager.create(col, { ...options, stoken: col.stoken });
    }
    col.__markSaved();
  }

  public getItemManager(col: Collection) {
    return new CollectionItemManager(this.etesync, this, col.encryptedCollection);
  }
}

export class CollectionItemManager {
  private readonly etesync: Account;
  private readonly collectionCryptoManager: CollectionCryptoManager;
  private readonly onlineManager: CollectionItemManagerOnline;

  constructor(etesync: Account, _collectionManager: CollectionManager, col: EncryptedCollection) {
    this.etesync = etesync;
    this.collectionCryptoManager = col.getCryptoManager(this.etesync.getCryptoManager());
    this.onlineManager = new CollectionItemManagerOnline(this.etesync, col);
  }

  public async create(meta: CollectionItemMetadata, content: Uint8Array): Promise<EncryptedCollectionItem> {
    return EncryptedCollectionItem.create(this.collectionCryptoManager, meta, content);
  }

  public async update(item: EncryptedCollectionItem, meta: CollectionItemMetadata, content: Uint8Array): Promise<void> {
    const cryptoManager = item.getCryptoManager(this.collectionCryptoManager);
    return item.update(cryptoManager, meta, content);
  }

  public async verify(item: EncryptedCollectionItem) {
    const cryptoManager = item.getCryptoManager(this.collectionCryptoManager);
    return item.verify(cryptoManager);
  }

  public async decryptMeta(item: EncryptedCollectionItem): Promise<CollectionItemMetadata> {
    const cryptoManager = item.getCryptoManager(this.collectionCryptoManager);
    return item.decryptMeta(cryptoManager);
  }

  public async decryptContent(item: EncryptedCollectionItem): Promise<Uint8Array> {
    const cryptoManager = item.getCryptoManager(this.collectionCryptoManager);
    return item.decryptContent(cryptoManager);
  }


  public async fetch(itemUid: base62, options: ItemFetchOptions) {
    return this.onlineManager.fetch(itemUid, options);
  }

  public async list(options: ItemFetchOptions) {
    return this.onlineManager.list(options);
  }

  public async fetchUpdates(items: EncryptedCollectionItem[], options?: ItemFetchOptions) {
    return this.onlineManager.fetchUpdates(items, options);
  }

  public async batch(items: EncryptedCollectionItem[], options?: ItemFetchOptions) {
    await this.onlineManager.batch(items, options);
    items.forEach((item) => {
      item.__markSaved();
    });
  }

  public async transaction(items: EncryptedCollectionItem[], deps?: EncryptedCollectionItem[], options?: ItemFetchOptions) {
    await this.onlineManager.transaction(items, deps, options);
    items.forEach((item) => {
      item.__markSaved();
    });
  }
}

export class CollectionInvitationManager {
  private readonly etesync: Account;
  private readonly onlineManager: CollectionInvitationManagerOnline;

  constructor(etesync: Account) {
    this.etesync = etesync;
    this.onlineManager = new CollectionInvitationManagerOnline(this.etesync);
  }

  public async listIncoming() {
    return this.onlineManager.listIncoming();
  }

  public async accept(invitation: SignedInvitationRead) {
    const mainCryptoManager = this.etesync.getCryptoManager();
    const identCryptoManager = this.etesync.getIdentityCryptoManager();
    const encryptionKey = identCryptoManager.decryptVerify(fromBase64(invitation.signedEncryptionKey), fromBase64(invitation.fromPubkey));
    const encryptedEncryptionKey = mainCryptoManager.encrypt(encryptionKey);
    return this.onlineManager.accept(invitation, encryptedEncryptionKey);
  }

  public async reject(invitation: SignedInvitationRead) {
    return this.onlineManager.reject(invitation);
  }

  public async fetchUserProfile(username: string): Promise<UserProfile> {
    return this.onlineManager.fetchUserProfile(username);
  }

  public async invite(col: Collection, username: string, pubkey: base64, accessLevel: CollectionAccessLevel): Promise<void> {
    const mainCryptoManager = this.etesync.getCryptoManager();
    const identCryptoManager = this.etesync.getIdentityCryptoManager();
    const invitation = await col.encryptedCollection.createInvitation(mainCryptoManager, identCryptoManager, username, fromBase64(pubkey), accessLevel);
    await this.onlineManager.invite(invitation);
  }
}

export class CollectionMemberManager {
  private readonly etesync: Account;
  private readonly onlineManager: CollectionMemberManagerOnline;

  constructor(etesync: Account, _collectionManager: CollectionManager, col: Collection) {
    this.etesync = etesync;
    this.onlineManager = new CollectionMemberManagerOnline(this.etesync, col.encryptedCollection);
  }

  public async list() {
    return this.onlineManager.list();
  }

  public async remove(username: string) {
    return this.onlineManager.remove(username);
  }

  public async leave() {
    return this.onlineManager.leave();
  }

  public async modifyAccessLevel(username: string, accessLevel: CollectionAccessLevel) {
    return this.onlineManager.modifyAccessLevel(username, accessLevel);
  }
}

export class Collection {
  private readonly cryptoManager: CollectionCryptoManager;
  public readonly encryptedCollection: EncryptedCollection;

  public constructor(cryptoManager: CollectionCryptoManager, encryptedCollection: EncryptedCollection) {
    this.cryptoManager = cryptoManager;
    this.encryptedCollection = encryptedCollection;
  }

  public async verify() {
    return this.encryptedCollection.verify(this.cryptoManager);
  }

  async update(meta: CollectionMetadata, content: Uint8Array): Promise<void> {
    return this.encryptedCollection.update(this.cryptoManager, meta, content);
  }

  public async getMeta(): Promise<CollectionMetadata> {
    return this.encryptedCollection.decryptMeta(this.cryptoManager);
  }

  public async getContent(): Promise<Uint8Array> {
    return this.encryptedCollection.decryptContent(this.cryptoManager);
  }

  public get uid() {
    return this.encryptedCollection.uid;
  }

  public get etag() {
    return this.encryptedCollection.etag;
  }

  public get stoken() {
    return this.encryptedCollection.stoken;
  }
}
