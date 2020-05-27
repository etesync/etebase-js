import URI from 'urijs';

import * as Constants from './Constants';

import { deriveKey, CryptoManager, sodium, concatArrayBuffers, AsymmetricCryptoManager } from './Crypto';
export { deriveKey, ready } from './Crypto';
import { HTTPError, NetworkError, IntegrityError } from './Exceptions';
export * from './Exceptions';
import { base62, base64, fromBase64, toBase64 } from './Helpers';
export { base62, base64, fromBase64, toBase64 } from './Helpers';

export { CURRENT_VERSION } from './Constants';

export type CollectionType = string;

export type ContentType = File | Blob | Uint8Array | string | null;

export interface CollectionMetadata {
  type: CollectionType;
  name: string;
  description: string;
  color: string;
}

export interface CollectionItemMetadata {
  type: string;
}

export type ChunkJson = [base64, base64?];

export interface ListResponse<T> {
  data: T;
}

export interface CollectionItemRevisionJsonWrite {
  uid: base64;
  meta: base64;

  chunks: ChunkJson[];
  deleted: boolean;
}

export interface CollectionItemRevisionJsonRead extends CollectionItemRevisionJsonWrite {
  chunks: ChunkJson[];
}

export interface CollectionItemJsonWrite {
  uid: base62;
  version: number;

  encryptionKey: base64;
  content: CollectionItemRevisionJsonWrite;

  stoken: string | null;
}

export interface CollectionItemJsonRead extends CollectionItemJsonWrite {
  content: CollectionItemRevisionJsonRead;
}

export enum CollectionAccessLevel {
  Admin = 'adm',
  ReadWrite = 'rw',
  ReadOnly = 'ro',
}

export interface CollectionJsonWrite {
  uid: base62;
  version: number;

  encryptionKey: base64;
  content: CollectionItemRevisionJsonWrite;

  stoken: string | null;
}

export interface CollectionJsonRead extends CollectionJsonWrite {
  accessLevel: CollectionAccessLevel;
  cstoken: string | null; // FIXME: hack, we shouldn't expose it here...

  content: CollectionItemRevisionJsonRead;
}

function genUidBase62(): base62 {
  const uid = sodium.to_base64(sodium.randombytes_buf(32)).substr(0, 24);
  // FIXME: not the best function, but we don't care about the bias for now
  return uid.replace(/-/g, 'a').replace(/_/g, 'b');
}

export class MainCryptoManager extends CryptoManager {
  constructor(key: Uint8Array, version: number = Constants.CURRENT_VERSION) {
    super(key, 'Main', version);
  }
}

export class CollectionCryptoManager extends CryptoManager {
  constructor(key: Uint8Array, version: number = Constants.CURRENT_VERSION) {
    super(key, 'Col', version);
  }
}

export class CollectionItemCryptoManager extends CryptoManager {
  constructor(key: Uint8Array, version: number = Constants.CURRENT_VERSION) {
    super(key, 'ColItem', version);
  }
}

export function getMainCryptoManager(mainEncryptionKey: Uint8Array, version: number) {
  return new MainCryptoManager(mainEncryptionKey, version);
}

export interface CollectionItemRevisionContent<M extends {}> {
  meta?: M;
  chunks?: ChunkJson[];
  deleted?: boolean;
}

class EncryptedRevision<CM extends CollectionCryptoManager | CollectionItemCryptoManager> {
  public uid: base64;
  public meta: Uint8Array;
  public deleted: boolean;

  public chunks: [base64, Uint8Array?][];

  constructor() {
    this.deleted = false;
  }

  public static async create<CM extends CollectionCryptoManager | CollectionItemCryptoManager>(cryptoManager: CM, additionalData: Uint8Array[] = [], meta: any, content: Uint8Array): Promise<EncryptedRevision<CM>> {
    const ret = new EncryptedRevision<CM>();
    const additionalDataMerged = additionalData.reduce((base, cur) => concatArrayBuffers(base, cur), new Uint8Array());
    ret.meta = cryptoManager.encrypt(sodium.from_string(JSON.stringify(meta)), additionalDataMerged);
    // FIXME: need to actually chunkify
    const encContent = cryptoManager.encryptDetached(content);
    ret.chunks = [[sodium.to_base64(encContent[0]), encContent[1]]];

    const mac = await ret.calculateMac(cryptoManager, additionalData);
    ret.uid = sodium.to_base64(mac);

    return ret;
  }

  public static deserialize<CM extends CollectionCryptoManager | CollectionItemCryptoManager>(json: CollectionItemRevisionJsonRead) {
    const { uid, meta, chunks, deleted } = json;
    const ret = new EncryptedRevision<CM>();
    ret.uid = uid;
    ret.meta = sodium.from_base64(meta);
    ret.deleted = deleted; // FIXME: this should also be part of the meta additional data too. Probably can remove from the major verification everything that's verified by meta.
    ret.chunks = chunks.map((chunk) => [chunk[0], (chunk[1]) ? sodium.from_base64(chunk[1]) : undefined]);

    return ret;
  }

  public serialize() {
    const ret: CollectionItemRevisionJsonWrite = {
      uid: this.uid,
      meta: sodium.to_base64(this.meta),
      deleted: this.deleted,

      chunks: this.chunks.map((chunk) => [chunk[0], (chunk[1]) ? sodium.to_base64(chunk[1]) : undefined]),
    };

    return ret;
  }

  public async verify(cryptoManager: CM, additionalData: Uint8Array[] = []) {
    const calculatedMac = await this.calculateMac(cryptoManager, additionalData);
    if (sodium.memcmp(
      sodium.from_base64(this.uid),
      calculatedMac
    )) {
      return true;
    } else {
      throw new IntegrityError(`mac verification failed. Expected: ${this.uid} got: ${sodium.to_base64(calculatedMac)}`);
    }
  }

  public async calculateMac(cryptoManager: CM, additionalData: Uint8Array[] = []) {
    const cryptoMac = cryptoManager.getCryptoMac();
    cryptoMac.update(Uint8Array.from([(this.deleted) ? 1 : 0]));
    additionalData.forEach((data) =>
      cryptoMac.update(data)
    );
    // FIXME: we are using the meta's mac here. Make sure we are doing it correctly.
    cryptoMac.update(this.meta.subarray(-1 * sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES));
    this.chunks.forEach((chunk) =>
      cryptoMac.update(sodium.from_base64(chunk[0]))
    );

    return cryptoMac.finalize();
  }

  public async decryptMeta(cryptoManager: CM, additionalData: Uint8Array[]): Promise<any> {
    const additionalDataMerged = additionalData.reduce((base, cur) => concatArrayBuffers(base, cur), new Uint8Array());
    return JSON.parse(sodium.to_string(cryptoManager.decrypt(this.meta, additionalDataMerged)));
  }

  public async decryptContent(cryptoManager: CM): Promise<Uint8Array> {
    return this.chunks.map((chunk) => cryptoManager.decryptDetached(chunk[1]!, sodium.from_base64(chunk[0])))
      .reduce((base, cur) => concatArrayBuffers(base, cur), new Uint8Array()) ?? new Uint8Array(0);
  }
}

export class EncryptedCollection {
  public uid: base62;
  public version: number;
  private encryptionKey: Uint8Array;
  private content: EncryptedRevision<CollectionCryptoManager>;

  public accessLevel: CollectionAccessLevel;
  public stoken: string | null;
  public cstoken: string | null; // FIXME: hack, we shouldn't expose it here...

  public static async create(parentCryptoManager: MainCryptoManager, meta: CollectionMetadata, content: Uint8Array): Promise<EncryptedCollection> {
    const ret = new EncryptedCollection();
    ret.uid = genUidBase62();
    ret.version = Constants.CURRENT_VERSION;
    ret.encryptionKey = parentCryptoManager.encrypt(sodium.crypto_aead_chacha20poly1305_ietf_keygen());

    ret.accessLevel = CollectionAccessLevel.Admin;
    ret.stoken = null;
    ret.cstoken = null;

    const cryptoManager = ret.getCryptoManager(parentCryptoManager);

    ret.content = await EncryptedRevision.create(cryptoManager, ret.getAdditionalMacData(), meta, content);

    return ret;
  }

  public static deserialize(json: CollectionJsonRead): EncryptedCollection {
    const { uid, cstoken, stoken, version, accessLevel, encryptionKey, content } = json;
    const ret = new EncryptedCollection();
    ret.uid = uid;
    ret.version = version;
    ret.encryptionKey = sodium.from_base64(encryptionKey);

    ret.accessLevel = accessLevel;
    ret.stoken = stoken;
    ret.cstoken = cstoken;

    ret.content = EncryptedRevision.deserialize(content);

    return ret;
  }

  public serialize() {
    const ret: CollectionJsonWrite = {
      uid: this.uid,
      version: this.version,
      encryptionKey: sodium.to_base64(this.encryptionKey),
      stoken: this.stoken,

      content: this.content.serialize(),
    };

    return ret;
  }

  public __markSaved() {
    this.stoken = this.content.uid;
  }

  public async update(cryptoManager: CollectionCryptoManager, meta: CollectionMetadata, content: Uint8Array): Promise<void> {
    this.content = await EncryptedRevision.create(cryptoManager, this.getAdditionalMacData(), meta, content);
  }

  public async verify(cryptoManager: CollectionCryptoManager) {
    return this.content.verify(cryptoManager, this.getAdditionalMacData());
  }

  public async decryptMeta(cryptoManager: CollectionCryptoManager): Promise<CollectionMetadata> {
    return this.content.decryptMeta(cryptoManager, this.getAdditionalMacData());
  }

  public async decryptContent(cryptoManager: CollectionCryptoManager): Promise<Uint8Array> {
    return this.content.decryptContent(cryptoManager);
  }

  public async createInvitation(parentCryptoManager: MainCryptoManager, identCryptoManager: AsymmetricCryptoManager, username: string, pubkey: Uint8Array, accessLevel: CollectionAccessLevel): Promise<SignedInvitationWrite> {
    const uid = sodium.randombytes_buf(32);
    const encryptionKey = parentCryptoManager.decrypt(this.encryptionKey);
    const signedEncryptionKey = identCryptoManager.encryptSign(encryptionKey, pubkey);
    const ret: SignedInvitationWrite = {
      version: Constants.CURRENT_VERSION,
      uid: toBase64(uid),
      username,
      collection: this.uid,
      accessLevel,

      signedEncryptionKey: toBase64(signedEncryptionKey),
    };

    return ret;
  }

  public getCryptoManager(parentCryptoManager: MainCryptoManager) {
    const encryptionKey = parentCryptoManager.decrypt(this.encryptionKey);

    return new CollectionCryptoManager(encryptionKey, this.version);
  }

  protected getAdditionalMacData() {
    return [sodium.from_string(this.uid)];
  }
}

export class EncryptedCollectionItem {
  public uid: base62;
  public version: number;
  private encryptionKey: Uint8Array;
  private content: EncryptedRevision<CollectionItemCryptoManager>;

  public stoken: string | null;

  public static async create(parentCryptoManager: CollectionCryptoManager, meta: CollectionItemMetadata, content: Uint8Array): Promise<EncryptedCollectionItem> {
    const ret = new EncryptedCollectionItem();
    ret.uid = genUidBase62();
    ret.version = Constants.CURRENT_VERSION;
    ret.encryptionKey = parentCryptoManager.encrypt(sodium.crypto_aead_chacha20poly1305_ietf_keygen());

    ret.stoken = null;

    const cryptoManager = ret.getCryptoManager(parentCryptoManager);

    ret.content = await EncryptedRevision.create(cryptoManager, ret.getAdditionalMacData(), meta, content);

    return ret;
  }

  public static deserialize(json: CollectionItemJsonRead): EncryptedCollectionItem {
    const { uid, version, encryptionKey, content } = json;
    const ret = new EncryptedCollectionItem();
    ret.uid = uid;
    ret.version = version;
    ret.encryptionKey = sodium.from_base64(encryptionKey);

    ret.stoken = json.stoken;

    ret.content = EncryptedRevision.deserialize(content);

    return ret;
  }

  public serialize() {
    const ret: CollectionItemJsonWrite = {
      uid: this.uid,
      version: this.version,
      encryptionKey: sodium.to_base64(this.encryptionKey),
      stoken: this.stoken,

      content: this.content.serialize(),
    };

    return ret;
  }

  public __markSaved() {
    this.stoken = this.content.uid;
  }

  public async update(cryptoManager: CollectionCryptoManager, meta: CollectionItemMetadata, content: Uint8Array): Promise<void> {
    this.content = await EncryptedRevision.create(cryptoManager, this.getAdditionalMacData(), meta, content);
  }

  public async verify(cryptoManager: CollectionCryptoManager) {
    return this.content.verify(cryptoManager, this.getAdditionalMacData());
  }

  public async decryptMeta(cryptoManager: CollectionCryptoManager): Promise<CollectionItemMetadata> {
    return this.content.decryptMeta(cryptoManager, this.getAdditionalMacData());
  }

  public async decryptContent(cryptoManager: CollectionCryptoManager): Promise<Uint8Array> {
    return this.content.decryptContent(cryptoManager);
  }

  public getCryptoManager(parentCryptoManager: MainCryptoManager) {
    const encryptionKey = parentCryptoManager.decrypt(this.encryptionKey);

    return new CollectionItemCryptoManager(encryptionKey, this.version);
  }

  protected getAdditionalMacData() {
    return [sodium.from_string(this.uid)];
  }
}

export interface SignedInvitationWrite {
  uid: base64;
  version: number;
  username: string;

  collection: base62;
  accessLevel: CollectionAccessLevel;

  signedEncryptionKey: base64;
}

export interface SignedInvitationRead extends SignedInvitationWrite {
  fromPubkey: base64;
}

export interface AcceptedInvitation {
  encryptionKey: base64;
}

export interface AccountData {
  version: number;
  key: base64;
  user: User;
  serverUrl: string;
  authToken?: string;
}

export class Account {
  private static readonly CURRENT_VERSION = 1;

  private mainKey: Uint8Array;
  private version: number;
  public user: User;
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
    const encryptedSeckey = mainCryptoManager.encrypt(identityCryptoManager.seckey);

    const loginResponse = await authenticator.signup(user, salt, loginCryptoManager.pubkey, identityCryptoManager.pubkey, encryptedSeckey);

    const ret = new this(mainKey, version);

    ret.user = loginResponse.user;
    ret.authToken = loginResponse.token;
    ret.serverUrl = serverUrl;

    return ret;
  }

  public static async login(userQuery: UsernameOrEmail, password: string, serverUrl?: string) {
    serverUrl = serverUrl ?? Constants.SERVER_URL;
    const authenticator = new Authenticator(serverUrl);
    const loginChallenge = await authenticator.getLoginChallenge(userQuery);

    const mainKey = deriveKey(fromBase64(loginChallenge.salt), password);
    const mainCryptoManager = getMainCryptoManager(mainKey, loginChallenge.version);
    const loginCryptoManager = mainCryptoManager.getLoginCryptoManager();

    const response = JSON.stringify({
      ...userQuery,
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
    const userQuery: UsernameOrEmail = {
      username: this.user.username,
    };
    const loginChallenge = await authenticator.getLoginChallenge(userQuery);

    const mainKey = this.mainKey;
    const mainCryptoManager = getMainCryptoManager(mainKey, loginChallenge.version);
    const loginCryptoManager = mainCryptoManager.getLoginCryptoManager();

    const response = JSON.stringify({
      ...userQuery,
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
    return new MainCryptoManager(this.mainKey, this.version);
  }
}

export class CollectionManager {
  private readonly etesync: Account;
  private readonly onlineManager: CollectionManagerOnline;

  constructor(etesync: Account) {
    this.etesync = etesync;
    this.onlineManager = new CollectionManagerOnline(this.etesync);
  }

  public async create(meta: CollectionMetadata, content: Uint8Array): Promise<EncryptedCollection> {
    return EncryptedCollection.create(this.etesync.getCryptoManager(), meta, content);
  }

  public async update(col: EncryptedCollection, meta: CollectionMetadata, content: Uint8Array): Promise<void> {
    const cryptoManager = col.getCryptoManager(this.etesync.getCryptoManager());
    return col.update(cryptoManager, meta, content);
  }

  public async verify(col: EncryptedCollection) {
    const cryptoManager = col.getCryptoManager(this.etesync.getCryptoManager());
    return col.verify(cryptoManager);
  }

  public async decryptMeta(col: EncryptedCollection): Promise<CollectionMetadata> {
    const cryptoManager = col.getCryptoManager(this.etesync.getCryptoManager());
    return col.decryptMeta(cryptoManager);
  }

  public async decryptContent(col: EncryptedCollection): Promise<Uint8Array> {
    const cryptoManager = col.getCryptoManager(this.etesync.getCryptoManager());
    return col.decryptContent(cryptoManager);
  }


  public async fetch(colUid: base62, options: FetchOptions) {
    return this.onlineManager.fetch(colUid, options);
  }

  public async list(options: FetchOptions) {
    return this.onlineManager.list(options);
  }

  // FIXME: Accept fetchOptions so stoken can be passed as well as inline for errors and etc
  // It's bad that what we call stoken for item it's just for the item and here it's for the whole collection
  public async upload(col: EncryptedCollection) {
    // If we have a stoken, it means we previously fetched it.
    if (col.stoken) {
      await this.onlineManager.update(col);
    } else {
      await this.onlineManager.create(col);
    }
    col.__markSaved();
  }

  public getItemManager(col: EncryptedCollection) {
    return new CollectionItemManager(this.etesync, this, col);
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

  public async fetch(invitationUid: string) {
    return this.onlineManager.fetch(invitationUid);
  }

  public async list() {
    return this.onlineManager.list();
  }

  public async accept(invitation: SignedInvitationRead) {
    const mainCryptoManager = this.etesync.getCryptoManager();
    const identCryptoManager = mainCryptoManager.getIdentityCryptoManager(fromBase64(this.etesync.user.encryptedSeckey));
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

  public async invite(col: EncryptedCollection, username: string, pubkey: base64, accessLevel: CollectionAccessLevel): Promise<void> {
    const mainCryptoManager = this.etesync.getCryptoManager();
    const identCryptoManager = mainCryptoManager.getIdentityCryptoManager(fromBase64(this.etesync.user.encryptedSeckey));
    const invitation = await col.createInvitation(mainCryptoManager, identCryptoManager, username, fromBase64(pubkey), accessLevel);
    await this.onlineManager.invite(invitation);
  }
}

export interface FetchOptions {
  cstoken?: string | null;
  inline?: boolean;
  limit?: number;
}

export interface ItemFetchOptions extends FetchOptions {
  withMainItem?: boolean;
}

class BaseNetwork {

  public static urlExtend(baseUrlIn: URI, segments: string[]): URI {
    const baseUrl = baseUrlIn.clone();
    for (const segment of segments) {
      baseUrl.segment(segment);
    }
    baseUrl.segment('');
    return baseUrl.normalize();
  }
  public apiBase: URI;

  constructor(apiBase: string) {
    this.apiBase = URI(apiBase).normalize();
  }

  public async newCall<T = any>(segments: string[] = [], extra: RequestInit = {}, apiBaseIn: URI = this.apiBase): Promise<T> {
    const apiBase = BaseNetwork.urlExtend(apiBaseIn, segments);

    extra = {
      ...extra,
      headers: {
        Accept: 'application/json',
        ...extra.headers,
      },
    };

    let response;
    try {
      response = await fetch(apiBase.toString(), extra);
    } catch (e) {
      throw new NetworkError(e.message);
    }

    const text = await response.text();
    let json: any;
    let body: any = text;
    try {
      json = JSON.parse(text);
      body = json;
    } catch (e) {
      body = text;
    }

    if (response.ok) {
      return body;
    } else {
      if (json) {
        throw new HTTPError(response.status, json.detail || json.non_field_errors || JSON.stringify(json));
      } else {
        throw new HTTPError(response.status, body);
      }
    }
  }
}

export interface User {
  username: string;
  email: string;
  pubkey: base64;
  encryptedSeckey: base64;
}

export interface UserProfile {
  pubkey: base64;
}

export type UsernameOrEmail = Pick<User, 'username'> | Pick<User, 'email'>;

export type LoginChallange = {
  challenge: string;
  salt: base64;
  version: number;
};

export type LoginChallangeResponse = {
  challenge: string;
  host: string;
} & UsernameOrEmail;

export type LoginResponse = {
  token: string;
  user: User;
};

class Authenticator extends BaseNetwork {
  constructor(apiBase: string) {
    super(apiBase);
    this.apiBase = BaseNetwork.urlExtend(this.apiBase, ['api', 'v1', 'authentication']);
  }

  public async signup(user: User, salt: Uint8Array, loginPubkey: Uint8Array, pubkey: Uint8Array, encryptedSeckey: Uint8Array): Promise<LoginResponse> {
    const extra = {
      method: 'post',
      headers: {
        'Content-Type': 'application/json;charset=UTF-8',
      },
      body: JSON.stringify({
        user,
        salt: toBase64(salt),
        loginPubkey: toBase64(loginPubkey),
        pubkey: toBase64(pubkey),
        encryptedSeckey: toBase64(encryptedSeckey),
      }),
    };

    return this.newCall<LoginResponse>(['signup'], extra);
  }

  public getLoginChallenge(userQuery: UsernameOrEmail): Promise<LoginChallange> {
    const extra = {
      method: 'post',
      headers: {
        'Content-Type': 'application/json;charset=UTF-8',
      },
      body: JSON.stringify(userQuery),
    };

    return this.newCall<LoginChallange>(['login_challenge'], extra);
  }

  public login(response: string, signature: Uint8Array): Promise<LoginResponse> {
    const extra = {
      method: 'post',
      headers: {
        'Content-Type': 'application/json;charset=UTF-8',
      },
      body: JSON.stringify({
        response: toBase64(response),
        signature: toBase64(signature),
      }),
    };

    return this.newCall<LoginResponse>(['login'], extra);
  }

  public logout(authToken: string): Promise<void> {
    const extra = {
      method: 'post',
      headers: {
        'Content-Type': 'application/json;charset=UTF-8',
        'Authorization': 'Token ' + authToken,
      },
    };

    return this.newCall(['logout'], extra);
  }
}

class BaseManager extends BaseNetwork {
  protected etesync: Account;

  constructor(etesync: Account, segments: string[]) {
    super(etesync.serverUrl);
    this.etesync = etesync;
    this.apiBase = BaseNetwork.urlExtend(this.apiBase, ['api', 'v1'].concat(segments));
  }

  public newCall<T = any>(segments: string[] = [], extra: RequestInit = {}, apiBase: URI = this.apiBase): Promise<T> {
    extra = {
      ...extra,
      headers: {
        'Content-Type': 'application/json;charset=UTF-8',
        'Authorization': 'Token ' + this.etesync.authToken,
        ...extra.headers,
      },
    };

    return super.newCall(segments, extra, apiBase);
  }

  protected urlFromFetchOptions(options?: FetchOptions) {
    if (!options) {
      return this.apiBase;
    }

    const { cstoken, inline, limit } = options;
    return this.apiBase.clone().search({
      cstoken: (cstoken !== null) ? cstoken : undefined,
      limit: (limit && (limit > 0)) ? limit : undefined,
      inline: inline,
    });
  }
}

class CollectionManagerOnline extends BaseManager {
  constructor(etesync: Account) {
    super(etesync, ['collection']);
  }

  // FIXME: do something with fetch options or remove?
  public async fetch(colUid: string, _options: FetchOptions): Promise<EncryptedCollection> {
    const json = await this.newCall<CollectionJsonRead>([colUid]);
    return EncryptedCollection.deserialize(json);
  }

  public async list(options: FetchOptions): Promise<EncryptedCollection[]> {
    const apiBase = this.urlFromFetchOptions(options);

    const json = await this.newCall<ListResponse<CollectionJsonRead[]>>(undefined, undefined, apiBase);
    return json.data.map((val) => EncryptedCollection.deserialize(val));
  }

  public create(collection: EncryptedCollection): Promise<{}> {
    const extra = {
      method: 'post',
      body: JSON.stringify(collection.serialize()),
    };

    return this.newCall(undefined, extra);
  }

  public update(collection: EncryptedCollection): Promise<{}> {
    const extra = {
      method: 'put',
      body: JSON.stringify(collection.serialize()),
    };

    return this.newCall([collection.uid], extra);
  }
}

class CollectionItemManagerOnline extends BaseManager {
  constructor(etesync: Account, col: EncryptedCollection) {
    super(etesync, ['collection', col.uid, 'item']);
  }

  // FIXME: do something with fetch options or remove?
  public async fetch(colUid: string, _options: ItemFetchOptions): Promise<EncryptedCollectionItem> {
    const json = await this.newCall<CollectionItemJsonRead>([colUid]);
    return EncryptedCollectionItem.deserialize(json);
  }

  public async list(options: ItemFetchOptions): Promise<EncryptedCollectionItem[]> {
    const { withMainItem } = options;
    const apiBase = this.urlFromFetchOptions(options);

    const json = await this.newCall<ListResponse<CollectionItemJsonRead[]>>(undefined, undefined, apiBase);
    let data = json.data;
    if (!withMainItem) {
      data = data.filter((x) => x.uid !== null);
    }
    return data.map((val) => EncryptedCollectionItem.deserialize(val));
  }

  public create(item: EncryptedCollectionItem): Promise<{}> {
    const extra = {
      method: 'post',
      body: JSON.stringify(item.serialize()),
    };

    return this.newCall(undefined, extra);
  }

  public async fetchUpdates(items: EncryptedCollectionItem[], options?: ItemFetchOptions): Promise<EncryptedCollectionItem[]> {
    const apiBase = this.urlFromFetchOptions(options);
    // We only use cstoken if available
    const wantStoken = !options?.cstoken;

    const extra = {
      method: 'post',
      body: JSON.stringify(items?.map((x) => ({ uid: x.uid, stoken: ((wantStoken) ? x.stoken : undefined) }))),
    };

    const json = await this.newCall<ListResponse<CollectionItemJsonRead[]>>(['fetch_updates'], extra, apiBase);
    const data = json.data;
    return data.map((val) => EncryptedCollectionItem.deserialize(val));
  }

  public batch(items: EncryptedCollectionItem[], options?: ItemFetchOptions): Promise<{}> {
    const apiBase = this.urlFromFetchOptions(options);

    const extra = {
      method: 'post',
      body: JSON.stringify({
        items: items.map((x) => x.serialize()),
      }),
    };

    return this.newCall(['batch'], extra, apiBase);
  }

  public transaction(items: EncryptedCollectionItem[], deps?: EncryptedCollectionItem[], options?: ItemFetchOptions): Promise<{}> {
    const apiBase = this.urlFromFetchOptions(options);

    const extra = {
      method: 'post',
      body: JSON.stringify({
        items: items.map((x) => x.serialize()),
        deps: deps?.map((x) => ({ uid: x.uid, stoken: x.stoken })),
      }),
    };

    return this.newCall(['transaction'], extra, apiBase);
  }
}

class CollectionInvitationManagerOnline extends BaseManager {
  constructor(etesync: Account) {
    super(etesync, ['invitation']);
  }

  public async fetch(invitationUid: string): Promise<SignedInvitationRead> {
    const json = await this.newCall<SignedInvitationRead>(['incoming', invitationUid]);
    return json;
  }

  public async list(): Promise<SignedInvitationRead[]> {
    const json = await this.newCall<SignedInvitationRead[]>(['incoming']);
    return json.map((val) => val);
  }

  public async accept(invitation: SignedInvitationRead, encryptionKey: Uint8Array): Promise<{}> {
    const extra = {
      method: 'post',
      body: JSON.stringify({
        encryptionKey: toBase64(encryptionKey),
      }),
    };

    return this.newCall(['incoming', invitation.uid, 'accept'], extra);
  }

  public async reject(invitation: SignedInvitationRead): Promise<{}> {
    const extra = {
      method: 'delete',
    };

    return this.newCall(['incoming', invitation.uid], extra);
  }

  public async fetchUserProfile(username: string): Promise<UserProfile> {
    const apiBase = this.apiBase.clone().search({
      username: username,
    });

    return this.newCall(['outgoing', 'fetch_user_profile'], undefined, apiBase);
  }

  public async invite(invitation: SignedInvitationWrite): Promise<{}> {
    const extra = {
      method: 'post',
      body: JSON.stringify(invitation),
    };

    return this.newCall(['outgoing'], extra);
  }

  public async disinvite(invitation: SignedInvitationRead): Promise<{}> {
    const extra = {
      method: 'delete',
    };

    return this.newCall(['outgoing', invitation.uid], extra);
  }
}
