import URI from 'urijs';

import * as Constants from './Constants';

import { CryptoManager, sodium, concatArrayBuffers } from './Crypto';
export { deriveKey, ready } from './Crypto';
import { HTTPError, NetworkError, IntegrityError } from './Exceptions';
export * from './Exceptions';
import { base62, base64url } from './Helpers';
export { base62, base64url, fromBase64, toBase64 } from './Helpers';

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

export type ChunkJson = [base64url, base64url?];

export interface CollectionItemRevisionJsonWrite {
  uid: base64url;
  meta: base64url;

  chunks: ChunkJson[];
  deleted: boolean;
}

export interface CollectionItemRevisionJsonRead extends CollectionItemRevisionJsonWrite {
  chunks: ChunkJson[];
}

export interface CollectionItemJsonWrite {
  uid: base62;
  version: number;

  encryptionKey: base64url;
  content: CollectionItemRevisionJsonWrite;
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

  encryptionKey: base64url;
  content: CollectionItemRevisionJsonWrite;
}

export interface CollectionJsonRead extends CollectionJsonWrite {
  accessLevel: CollectionAccessLevel;
  stoken: string;

  content: CollectionItemRevisionJsonRead;
}

function genUidBase62(): base62 {
  const uid = sodium.to_base64(sodium.randombytes_buf(32)).substr(0, 24);
  // FIXME: not the best function, but we don't care about the bias for now
  return uid.replace('-', 'a').replace('_', 'b');
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
  public uid: base64url;
  public meta: Uint8Array;
  public deleted: boolean;

  public chunks: [base64url, Uint8Array?][];

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

  public static async create(parentCryptoManager: MainCryptoManager, meta: CollectionMetadata, content: Uint8Array): Promise<EncryptedCollection> {
    const ret = new EncryptedCollection();
    ret.uid = genUidBase62();
    ret.version = Constants.CURRENT_VERSION;
    ret.encryptionKey = parentCryptoManager.encrypt(sodium.crypto_aead_chacha20poly1305_ietf_keygen());

    ret.accessLevel = CollectionAccessLevel.Admin;
    ret.stoken = null;

    const cryptoManager = ret.getCryptoManager(parentCryptoManager);

    ret.content = await EncryptedRevision.create(cryptoManager, ret.getAdditionalMacData(), meta, content);

    return ret;
  }

  public static deserialize(json: CollectionJsonRead): EncryptedCollection {
    const { uid, stoken, version, accessLevel, encryptionKey, content } = json;
    const ret = new EncryptedCollection();
    ret.uid = uid;
    ret.version = version;
    ret.encryptionKey = sodium.from_base64(encryptionKey);

    ret.accessLevel = accessLevel;
    ret.stoken = stoken;

    ret.content = EncryptedRevision.deserialize(content);

    return ret;
  }

  public serialize() {
    const ret: CollectionJsonWrite = {
      uid: this.uid,
      version: this.version,
      encryptionKey: sodium.to_base64(this.encryptionKey),

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

    ret.stoken = null;

    ret.content = EncryptedRevision.deserialize(content);

    return ret;
  }

  public serialize() {
    const ret: CollectionItemJsonWrite = {
      uid: this.uid,
      version: this.version,
      encryptionKey: sodium.to_base64(this.encryptionKey),

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

export class Account {
  private mainEncryptionKey: Uint8Array;
  private version: number;
  public serverUrl: string;
  public authToken: string | null;

  private constructor(mainEncryptionKey: Uint8Array, version: number) {
    this.mainEncryptionKey = mainEncryptionKey;
    this.version = version;
    this.authToken = null;
  }

  public static async login(username: string, password: string, serverUrl?: string) {
    serverUrl = serverUrl ?? Constants.SERVER_URL;
    const authenticator = new Authenticator(serverUrl);

    // in reality these will be fetched:
    const salt = sodium.randombytes_buf(32);
    const version = 1;
    const ret = new this(salt, version);

    // FIXME: in reality, password would be derived from the encryption key
    const authToken = await authenticator.getAuthToken(username, password);
    ret.authToken = authToken;
    ret.serverUrl = serverUrl;

    return ret;
  }

  public logout() {
    this.version = -1;
    this.mainEncryptionKey = new Uint8Array();
    this.authToken = null;
  }

  public getCollectionManager() {
    return new CollectionManager(this);
  }

  public getCryptoManager() {
    return new MainCryptoManager(this.mainEncryptionKey, this.version);
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

  public async upload(col: EncryptedCollection) {
    // If we have a stoken, it means we previously fetched it.
    if (col.stoken) {
      await this.onlineManager.update(col);
      col.__markSaved();
    } else {
      await this.onlineManager.create(col);
      col.__markSaved();
    }
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

  public async upload(items: EncryptedCollectionItem[]) {
    for (const item of items) {
      // If we have a stoken, it means we previously fetched it.
      if (item.stoken) {
        await this.onlineManager.update(item);
        item.__markSaved();
      } else {
        await this.onlineManager.create(item);
        item.__markSaved();
      }
    }
  }
}

export interface FetchOptions {
  syncToken?: string;
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

  public newCall<T = any>(segments: string[] = [], extra: RequestInit = {}, apiBaseIn: URI = this.apiBase): Promise<T> {
    const apiBase = BaseNetwork.urlExtend(apiBaseIn, segments);

    extra = {
      ...extra,
      headers: {
        Accept: 'application/json',
        ...extra.headers,
      },
    };

    return new Promise((resolve, reject) => {
      fetch(apiBase.toString(), extra).then((response) => {
        response.text().then((text) => {
          let json: any;
          let body: any = text;
          try {
            json = JSON.parse(text);
            body = json;
          } catch (e) {
            body = text;
          }

          if (response.ok) {
            resolve(body);
          } else {
            if (json) {
              reject(new HTTPError(response.status, json.detail || json.non_field_errors || JSON.stringify(json)));
            } else {
              reject(new HTTPError(response.status, body));
            }
          }
        }).catch((error) => {
          reject(error);
        });
      }).catch((error) => {
        reject(new NetworkError(error.message));
      });
    });
  }
}

class Authenticator extends BaseNetwork {
  public getAuthToken(username: string, password: string): Promise<string> {
    return new Promise((resolve, reject) => {
      // FIXME: should be FormData but doesn't work for whatever reason
      const form = 'username=' + encodeURIComponent(username) +
        '&password=' + encodeURIComponent(password);
      const extra = {
        method: 'post',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
        },
        body: form,
      };

      this.newCall<{token: string}>(['api-token-auth'], extra).then((json) => {
        resolve(json.token);
      }).catch((error: Error) => {
        reject(error);
      });
    });
  }

  public invalidateToken(authToken: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const extra = {
        method: 'post',
        headers: {
          'Content-Type': 'application/json;charset=UTF-8',
          'Authorization': 'Token ' + authToken,
        },
      };

      this.newCall<{token: string}>(['api', 'logout'], extra).then(() => {
        resolve();
      }).catch((error: Error) => {
        reject(error);
      });
    });
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
}

class CollectionManagerOnline extends BaseManager {
  constructor(etesync: Account) {
    super(etesync, ['collection']);
  }

  public fetch(colUid: string, options: FetchOptions): Promise<EncryptedCollection> {
    return new Promise((resolve, reject) => {
      this.newCall<CollectionJsonRead>([colUid]).then((json) => {
        const collection = EncryptedCollection.deserialize(json);
        resolve(collection);
      }).catch((error: Error) => {
        reject(error);
      });
    });
  }

  public list(options: FetchOptions): Promise<EncryptedCollection[]> {
    const { syncToken, inline, limit } = options;
    const apiBase = this.apiBase.clone().search({
      syncToken: (syncToken !== null) ? syncToken : undefined,
      limit: (limit && (limit > 0)) ? limit : undefined,
      inline: inline,
    });

    return new Promise((resolve, reject) => {
      this.newCall<CollectionJsonRead[]>(undefined, undefined, apiBase).then((json) => {
        resolve(json.map((val) => {
          const collection = EncryptedCollection.deserialize(val);
          return collection;
        }));
      }).catch((error: Error) => {
        reject(error);
      });
    });
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

  public fetch(colUid: string, options: ItemFetchOptions): Promise<EncryptedCollectionItem> {
    return new Promise((resolve, reject) => {
      this.newCall<CollectionItemJsonRead>([colUid]).then((json) => {
        const collection = EncryptedCollectionItem.deserialize(json);
        resolve(collection);
      }).catch((error: Error) => {
        reject(error);
      });
    });
  }

  public list(options: ItemFetchOptions): Promise<EncryptedCollectionItem[]> {
    const { syncToken, inline, limit, withMainItem } = options;
    const apiBase = this.apiBase.clone().search({
      syncToken: (syncToken !== null) ? syncToken : undefined,
      limit: (limit && (limit > 0)) ? limit : undefined,
      inline: inline,
    });

    return new Promise((resolve, reject) => {
      this.newCall<CollectionItemJsonRead[]>(undefined, undefined, apiBase).then((json) => {
        if (!withMainItem) {
          json = json.filter((x) => x.uid !== null);
        }
        resolve(json.map((val) => {
          const collection = EncryptedCollectionItem.deserialize(val);
          return collection;
        }));
      }).catch((error: Error) => {
        reject(error);
      });
    });
  }

  public create(collection: EncryptedCollectionItem): Promise<{}> {
    const extra = {
      method: 'post',
      body: JSON.stringify(collection.serialize()),
    };

    return this.newCall(undefined, extra);
  }

  public update(collection: EncryptedCollectionItem): Promise<{}> {
    const extra = {
      method: 'put',
      body: JSON.stringify(collection.serialize()),
    };

    return this.newCall([collection.uid], extra);
  }
}
