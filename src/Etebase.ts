import URI from "urijs";

import * as Constants from "./Constants";

import { deriveKey, concatArrayBuffers, BoxCryptoManager, ready } from "./Crypto";
export { ready, getPrettyFingerprint } from "./Crypto";
export * from "./Exceptions";
import { base64, fromBase64, toBase64, fromString, toString, randomBytes, symmetricKeyLength, msgpackEncode, msgpackDecode } from "./Helpers";
export { base64, fromBase64, toBase64, randomBytes } from "./Helpers";

import {
  CollectionAccessLevel,
  CollectionCryptoManager,
  CollectionItemCryptoManager,
  CollectionMetadata,
  CollectionItemMetadata,
  EncryptedCollection,
  EncryptedCollectionItem,
  getMainCryptoManager,
  StorageCryptoManager,
} from "./EncryptedModels";
export * from "./EncryptedModels"; // FIXME: cherry-pick what we export
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
  MemberFetchOptions,
  InvitationFetchOptions,
  RevisionsFetchOptions,
} from "./OnlineManagers";
import { ProgrammingError } from "./Exceptions";
export { User, FetchOptions, ItemFetchOptions } from "./OnlineManagers";

import { CURRENT_VERSION } from "./Constants";
export { CURRENT_VERSION } from "./Constants";

export interface AccountData {
  version: number;
  key: Uint8Array;
  user: LoginResponseUser;
  serverUrl: string;
  authToken?: string;
}

export interface AccountDataStored {
  version: number;
  encryptedData: Uint8Array;
}

export class Account {
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
    await ready;

    serverUrl = serverUrl ?? Constants.SERVER_URL;
    const authenticator = new Authenticator(serverUrl);
    const version = CURRENT_VERSION;
    const salt = randomBytes(32);

    const mainKey = await deriveKey(salt, password);
    const mainCryptoManager = getMainCryptoManager(mainKey, version);
    const loginCryptoManager = mainCryptoManager.getLoginCryptoManager();

    const identityCryptoManager = BoxCryptoManager.keygen();

    const accountKey = randomBytes(symmetricKeyLength);
    const encryptedContent = mainCryptoManager.encrypt(concatArrayBuffers(accountKey, identityCryptoManager.privkey));

    const loginResponse = await authenticator.signup(user, salt, loginCryptoManager.pubkey, identityCryptoManager.pubkey, encryptedContent);

    const ret = new this(mainKey, version);

    ret.user = loginResponse.user;
    ret.authToken = loginResponse.token;
    ret.serverUrl = serverUrl;

    return ret;
  }

  public static async login(username: string, password: string, serverUrl?: string) {
    await ready;

    serverUrl = serverUrl ?? Constants.SERVER_URL;
    const authenticator = new Authenticator(serverUrl);
    const loginChallenge = await authenticator.getLoginChallenge(username);

    const mainKey = await deriveKey(loginChallenge.salt, password);
    const mainCryptoManager = getMainCryptoManager(mainKey, loginChallenge.version);
    const loginCryptoManager = mainCryptoManager.getLoginCryptoManager();

    const response = msgpackEncode({
      username,
      challenge: loginChallenge.challenge,
      host: URI(serverUrl).host(),
      action: "login",
    });

    const loginResponse = await authenticator.login(response, loginCryptoManager.signDetached(response));

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

    const response = msgpackEncode({
      username,
      challenge: loginChallenge.challenge,
      host: URI(serverUrl).host(),
      action: "login",
    });

    const loginResponse = await authenticator.login(response, loginCryptoManager.signDetached(response));

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
    const serverUrl = this.serverUrl;
    const authenticator = new Authenticator(serverUrl);
    const username = this.user.username;
    const loginChallenge = await authenticator.getLoginChallenge(username);

    const oldMainCryptoManager = getMainCryptoManager(this.mainKey, this.version);
    const content = oldMainCryptoManager.decrypt(this.user.encryptedContent);
    const oldLoginCryptoManager = oldMainCryptoManager.getLoginCryptoManager();

    const mainKey = await deriveKey(loginChallenge.salt, password);
    const mainCryptoManager = getMainCryptoManager(mainKey, this.version);
    const loginCryptoManager = mainCryptoManager.getLoginCryptoManager();

    const encryptedContent = mainCryptoManager.encrypt(content);

    const response = msgpackEncode({
      username,
      challenge: loginChallenge.challenge,
      host: URI(serverUrl).host(),
      action: "changePassword",

      loginPubkey: loginCryptoManager.pubkey,
      encryptedContent: encryptedContent,
    });

    await authenticator.changePassword(this.authToken!, response, oldLoginCryptoManager.signDetached(response));

    this.mainKey = mainKey;
    this.user.encryptedContent = encryptedContent;
  }

  public async save(encryptionKey_?: Uint8Array): Promise<base64> {
    const version = CURRENT_VERSION;
    const encryptionKey = encryptionKey_ ?? new Uint8Array(32);
    const cryptoManager = new StorageCryptoManager(encryptionKey, version);

    const content: AccountData = {
      user: this.user,
      authToken: this.authToken!!,
      serverUrl: this.serverUrl,
      version: this.version,
      key: cryptoManager.encrypt(this.mainKey),
    };

    const ret: AccountDataStored = {
      version,
      encryptedData: cryptoManager.encrypt(msgpackEncode(content), Uint8Array.from([version])),
    };

    return toBase64(msgpackEncode(ret));
  }

  public static async restore(accountDataStored_: base64, encryptionKey_?: Uint8Array) {
    await ready;

    const encryptionKey = encryptionKey_ ?? new Uint8Array(32);
    const accountDataStored = msgpackDecode(fromBase64(accountDataStored_)) as AccountDataStored;

    const cryptoManager = new StorageCryptoManager(encryptionKey, accountDataStored.version);

    const accountData = msgpackDecode(
      cryptoManager.decrypt(accountDataStored.encryptedData, Uint8Array.from([accountDataStored.version]))
    ) as AccountData;

    const ret = new this(cryptoManager.decrypt(accountData.key), accountData.version);
    ret.user = accountData.user;
    ret.authToken = accountData.authToken ?? null;
    ret.serverUrl = accountData.serverUrl;

    return ret;
  }

  public getCollectionManager() {
    return new CollectionManager(this);
  }

  public _getCryptoManager() {
    // FIXME: cache this
    const mainCryptoManager = getMainCryptoManager(this.mainKey, this.version);
    const content = mainCryptoManager.decrypt(this.user.encryptedContent);
    return mainCryptoManager.getAccountCryptoManager(content.subarray(0, symmetricKeyLength));
  }

  public _getIdentityCryptoManager() {
    // FIXME: cache this
    const mainCryptoManager = getMainCryptoManager(this.mainKey, this.version);
    const content = mainCryptoManager.decrypt(this.user.encryptedContent);
    return mainCryptoManager.getIdentityCryptoManager(content.subarray(symmetricKeyLength));
  }
}

const defaultCacheOptions = {
  saveContent: true,
};

export class CollectionManager {
  private readonly etebase: Account;
  private readonly onlineManager: CollectionManagerOnline;

  constructor(etebase: Account) {
    this.etebase = etebase;
    this.onlineManager = new CollectionManagerOnline(this.etebase);
  }

  public async create(meta: CollectionMetadata, content: Uint8Array | string): Promise<Collection> {
    const uintcontent = (content instanceof Uint8Array) ? content : fromString(content);
    const mainCryptoManager = this.etebase._getCryptoManager();
    const encryptedCollection = await EncryptedCollection.create(mainCryptoManager, meta, uintcontent);
    return new Collection(encryptedCollection.getCryptoManager(mainCryptoManager), encryptedCollection);
  }

  public async fetch(colUid: base64, options?: FetchOptions) {
    const mainCryptoManager = this.etebase._getCryptoManager();
    const encryptedCollection = await this.onlineManager.fetch(colUid, options);
    return new Collection(encryptedCollection.getCryptoManager(mainCryptoManager), encryptedCollection);
  }

  public async list(options?: FetchOptions) {
    const mainCryptoManager = this.etebase._getCryptoManager();
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
      const itemOnlineManager = new CollectionItemManagerOnline(this.etebase, col);
      await itemOnlineManager.batch([col.item], undefined, options);
    } else {
      await this.onlineManager.create(col, options);
    }
    col.__markSaved();
  }

  public async transaction(collection: Collection, options?: FetchOptions) {
    const col = collection.encryptedCollection;
    // If we have a etag, it means we previously fetched it.
    if (col.etag) {
      const itemOnlineManager = new CollectionItemManagerOnline(this.etebase, col);
      await itemOnlineManager.transaction([col.item], undefined, options);
    } else {
      await this.onlineManager.create(col, options);
    }
    col.__markSaved();
  }

  public async cacheSave(collection: Collection, options = defaultCacheOptions): Promise<Uint8Array> {
    return collection.encryptedCollection.cacheSave(options.saveContent);
  }

  public async cacheLoad(cache: Uint8Array): Promise<Collection> {
    const encCol = EncryptedCollection.cacheLoad(cache);
    const mainCryptoManager = this.etebase._getCryptoManager();
    return new Collection(encCol.getCryptoManager(mainCryptoManager), encCol);
  }

  public getItemManager(col: Collection) {
    return new CollectionItemManager(this.etebase, this, col.encryptedCollection);
  }
}

export class CollectionItemManager {
  private readonly collectionCryptoManager: CollectionCryptoManager;
  private readonly onlineManager: CollectionItemManagerOnline;
  private readonly collectionUid: string; // The uid of the collection this item belongs to

  constructor(etebase: Account, _collectionManager: CollectionManager, col: EncryptedCollection) {
    this.collectionCryptoManager = col.getCryptoManager(etebase._getCryptoManager());
    this.onlineManager = new CollectionItemManagerOnline(etebase, col);
    this.collectionUid = col.uid;
  }

  public async create(meta: CollectionItemMetadata, content: Uint8Array | string): Promise<CollectionItem> {
    const uintcontent = (content instanceof Uint8Array) ? content : fromString(content);
    const encryptedItem = await EncryptedCollectionItem.create(this.collectionCryptoManager, meta, uintcontent);
    return new CollectionItem(this.collectionUid, encryptedItem.getCryptoManager(this.collectionCryptoManager), encryptedItem);
  }

  public async fetch(itemUid: base64, options?: ItemFetchOptions) {
    const encryptedItem = await this.onlineManager.fetch(itemUid, options);
    return new CollectionItem(this.collectionUid, encryptedItem.getCryptoManager(this.collectionCryptoManager), encryptedItem);
  }

  public async list(options?: ItemFetchOptions) {
    const ret = await this.onlineManager.list(options);
    return {
      ...ret,
      data: ret.data.map((x) => new CollectionItem(this.collectionUid, x.getCryptoManager(this.collectionCryptoManager), x)),
    };
  }

  public async itemRevisions(item: CollectionItem, options?: RevisionsFetchOptions) {
    const ret = await this.onlineManager.itemRevisions(item.encryptedItem, options);
    return {
      ...ret,
      data: ret.data.map((x) => new CollectionItem(this.collectionUid, x.getCryptoManager(this.collectionCryptoManager), x)),
    };
  }

  // Prepare the items for upload and verify they belong to the right collection
  private itemsPrepareForUpload(items?: CollectionItem[] | null) {
    return items?.map((x) => {
      if (x.collectionUid !== this.collectionUid) {
        throw new ProgrammingError(`Uploading an item belonging to collection ${x.collectionUid} to another collection (${this.collectionUid}) is not allowed!`);
      }
      return x.encryptedItem;
    });
  }

  public async fetchUpdates(items: CollectionItem[], options?: ItemFetchOptions) {
    const ret = await this.onlineManager.fetchUpdates(this.itemsPrepareForUpload(items)!, options);
    return {
      ...ret,
      data: ret.data.map((x) => new CollectionItem(this.collectionUid, x.getCryptoManager(this.collectionCryptoManager), x)),
    };
  }

  public async batch(items: CollectionItem[], deps?: CollectionItem[] | null, options?: ItemFetchOptions) {
    await this.onlineManager.batch(this.itemsPrepareForUpload(items)!, this.itemsPrepareForUpload(deps), options);
    items.forEach((item) => {
      item.encryptedItem.__markSaved();
    });
  }

  public async transaction(items: CollectionItem[], deps?: CollectionItem[] | null, options?: ItemFetchOptions) {
    await this.onlineManager.transaction(this.itemsPrepareForUpload(items)!, this.itemsPrepareForUpload(deps), options);
    items.forEach((item) => {
      item.encryptedItem.__markSaved();
    });
  }

  public async cacheSave(item: CollectionItem, options = defaultCacheOptions): Promise<Uint8Array> {
    return item.encryptedItem.cacheSave(options.saveContent);
  }

  public async cacheLoad(cache: Uint8Array): Promise<CollectionItem> {
    const encItem = EncryptedCollectionItem.cacheLoad(cache);
    return new CollectionItem(this.collectionUid, encItem.getCryptoManager(this.collectionCryptoManager), encItem);
  }
}
export interface SignedInvitation {
  uid: base64;
  version: number;
  username: string;

  collection: base64;
  accessLevel: CollectionAccessLevel;

  signedEncryptionKey: Uint8Array;
  fromPubkey: Uint8Array;
}

export class CollectionInvitationManager {
  private readonly etebase: Account;
  private readonly onlineManager: CollectionInvitationManagerOnline;

  constructor(etebase: Account) {
    this.etebase = etebase;
    this.onlineManager = new CollectionInvitationManagerOnline(this.etebase);
  }

  public async listIncoming(options?: InvitationFetchOptions) {
    return await this.onlineManager.listIncoming(options);
  }

  public async listOutgoing(options?: InvitationFetchOptions) {
    return await this.onlineManager.listOutgoing(options);
  }

  public async accept(invitation: SignedInvitation) {
    const mainCryptoManager = this.etebase._getCryptoManager();
    const identCryptoManager = this.etebase._getIdentityCryptoManager();
    const encryptionKey = identCryptoManager.decrypt(invitation.signedEncryptionKey, invitation.fromPubkey);
    const encryptedEncryptionKey = mainCryptoManager.encrypt(encryptionKey);
    return this.onlineManager.accept(invitation, encryptedEncryptionKey);
  }

  public async reject(invitation: SignedInvitation) {
    return this.onlineManager.reject(invitation);
  }

  public async fetchUserProfile(username: string) {
    return await this.onlineManager.fetchUserProfile(username);
  }

  public async invite(col: Collection, username: string, pubkey: Uint8Array, accessLevel: CollectionAccessLevel): Promise<void> {
    const mainCryptoManager = this.etebase._getCryptoManager();
    const identCryptoManager = this.etebase._getIdentityCryptoManager();
    const invitation = await col.encryptedCollection.createInvitation(mainCryptoManager, identCryptoManager, username, pubkey, accessLevel);
    await this.onlineManager.invite(invitation);
  }

  public async disinvite(invitation: SignedInvitation) {
    return this.onlineManager.disinvite(invitation);
  }

  public get pubkey() {
    const identCryptoManager = this.etebase._getIdentityCryptoManager();
    return identCryptoManager.pubkey;
  }
}

export class CollectionMemberManager {
  private readonly etebase: Account;
  private readonly onlineManager: CollectionMemberManagerOnline;

  constructor(etebase: Account, _collectionManager: CollectionManager, col: Collection) {
    this.etebase = etebase;
    this.onlineManager = new CollectionMemberManagerOnline(this.etebase, col.encryptedCollection);
  }

  public async list(options?: MemberFetchOptions) {
    return this.onlineManager.list(options);
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

export enum OutputFormat {
  Uint8Array,
  String,
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

  public async setMeta(meta: CollectionMetadata): Promise<void> {
    await this.encryptedCollection.setMeta(this.cryptoManager, meta);
  }

  public async getMeta(): Promise<CollectionMetadata> {
    return this.encryptedCollection.decryptMeta(this.cryptoManager);
  }

  public async setContent(content: Uint8Array | string): Promise<void> {
    const uintcontent = (content instanceof Uint8Array) ? content : fromString(content);
    await this.encryptedCollection.setContent(this.cryptoManager, uintcontent);
  }

  public async getContent(outputFormat?: OutputFormat.Uint8Array): Promise<Uint8Array>;
  public async getContent(outputFormat?: OutputFormat.String): Promise<string>;
  public async getContent(outputFormat: OutputFormat = OutputFormat.Uint8Array): Promise<any> {
    const ret = await this.encryptedCollection.decryptContent(this.cryptoManager);
    switch (outputFormat) {
      case OutputFormat.Uint8Array:
        return ret;
      case OutputFormat.String:
        return toString(ret);
      default:
        throw new Error("Bad output format");
    }
  }

  public async delete(preserveContent = false): Promise<void> {
    if (!preserveContent) {
      await this.setContent(Uint8Array.from([]));
    }
    await this.encryptedCollection.delete(this.cryptoManager);
  }

  public get uid() {
    return this.encryptedCollection.uid;
  }

  public get etag() {
    return this.encryptedCollection.etag;
  }

  public get isDeleted() {
    return this.encryptedCollection.isDeleted;
  }

  public get stoken() {
    return this.encryptedCollection.stoken;
  }

  public get item() {
    const encryptedItem = this.encryptedCollection.item;
    return new CollectionItem(this.uid, encryptedItem.getCryptoManager(this.cryptoManager), encryptedItem);
  }
}

export class CollectionItem {
  private readonly cryptoManager: CollectionItemCryptoManager;
  public readonly encryptedItem: EncryptedCollectionItem;
  public readonly collectionUid: string; // The uid of the collection this item belongs to

  public constructor(collectionUid: string, cryptoManager: CollectionItemCryptoManager, encryptedItem: EncryptedCollectionItem) {
    this.cryptoManager = cryptoManager;
    this.encryptedItem = encryptedItem;
    this.collectionUid = collectionUid;
  }

  public async verify() {
    return this.encryptedItem.verify(this.cryptoManager);
  }

  public async setMeta(meta: CollectionItemMetadata): Promise<void> {
    await this.encryptedItem.setMeta(this.cryptoManager, meta);
  }

  public async getMeta(): Promise<CollectionItemMetadata> {
    return this.encryptedItem.decryptMeta(this.cryptoManager);
  }

  public async setContent(content: Uint8Array | string): Promise<void> {
    const uintcontent = (content instanceof Uint8Array) ? content : fromString(content);
    await this.encryptedItem.setContent(this.cryptoManager, uintcontent);
  }

  public async getContent(outputFormat?: OutputFormat.Uint8Array): Promise<Uint8Array>;
  public async getContent(outputFormat?: OutputFormat.String): Promise<string>;
  public async getContent(outputFormat: OutputFormat = OutputFormat.Uint8Array): Promise<any> {
    const ret = await this.encryptedItem.decryptContent(this.cryptoManager);
    switch (outputFormat) {
      case OutputFormat.Uint8Array:
        return ret;
      case OutputFormat.String:
        return toString(ret);
      default:
        throw new Error("Bad output format");
    }
  }

  public async delete(preserveContent = false): Promise<void> {
    if (!preserveContent) {
      await this.setContent(Uint8Array.from([]));
    }
    await this.encryptedItem.delete(this.cryptoManager);
  }

  public get uid() {
    return this.encryptedItem.uid;
  }

  public get etag() {
    return this.encryptedItem.etag;
  }

  public get isDeleted() {
    return this.encryptedItem.isDeleted;
  }

  public _clone() {
    return new CollectionItem(this.collectionUid, this.cryptoManager, EncryptedCollectionItem.deserialize(this.encryptedItem.serialize()));
  }
}
