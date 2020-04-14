import URI from 'urijs';

import * as Constants from './Constants';

import { CryptoManager, sodium, concatArrayBuffers } from './Crypto';
export { deriveKey, ready } from './Crypto';
import { HTTPError, NetworkError, IntegrityError } from './Exceptions';
export * from './Exceptions';
import { base62, base64url } from './Helpers';
export { base62, base64url, from_base64, to_base64 } from './Helpers';

export { CURRENT_VERSION } from './Constants';

export interface Credentials {
  username: string;
  authToken: string;
}

export type CollectionType = string;

export type ContentType = File | Blob | Uint8Array | string | null;

export interface CollectionMetadata {
  type: CollectionType;
  name: string;
  description: string;
  color: string;
}

export interface CollectionItemRevisionJsonWrite {
  uid: base64url;
  meta: base64url;

  chunks: base64url[];
  deleted: boolean;

  chunksData?: base64url[];
}

export interface CollectionItemRevisionJsonRead extends CollectionItemRevisionJsonWrite {
  chunksUrls?: string[];
}

export interface CollectionItemJson {
  uid: base62;
  version: number;
  encryptionKey: base64url;

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
  ctag: string;

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
  chunks?: base64url[];
  deleted?: boolean;
}

class EncryptedRevision<CM extends CollectionCryptoManager | CollectionItemCryptoManager> {
  public uid: base64url;
  public meta: Uint8Array;
  public deleted: boolean;

  public chunks: base64url[];
  public chunksData?: Uint8Array[];
  public chunksUrls?: string[];

  constructor() {
    this.deleted = false;
  }

  public static async create<CM extends CollectionCryptoManager | CollectionItemCryptoManager>(cryptoManager: CM, additionalData: Uint8Array[] = [], meta: any, content: Uint8Array): Promise<EncryptedRevision<CM>> {
    const ret = new EncryptedRevision<CM>();
    const additionalDataMerged = additionalData.reduce((base, cur) => concatArrayBuffers(base, cur), new Uint8Array());
    ret.meta = cryptoManager.encrypt(sodium.from_string(JSON.stringify(meta)), additionalDataMerged);
    // FIXME: need to actually chunkify
    const encContent = cryptoManager.encryptDetached(content);
    ret.chunks = [sodium.to_base64(encContent[0])];
    ret.chunksData = [encContent[1]];

    const mac = await ret.calculateMac(cryptoManager, additionalData);
    ret.uid = sodium.to_base64(mac);

    return ret;
  }

  public static deserialize<CM extends CollectionCryptoManager | CollectionItemCryptoManager>(json: CollectionItemRevisionJsonRead) {
    const { uid, meta, chunks, deleted, chunksData, chunksUrls } = json;
    const ret = new EncryptedRevision<CM>();
    ret.uid = uid;
    ret.meta = sodium.from_base64(meta);
    ret.deleted = deleted; // FIXME: this should also be part of the meta additional data too. Probably can remove from the major verification everything that's verified by meta.
    ret.chunks = chunks;
    ret.chunksData = chunksData?.map((x) => sodium.from_base64(x));
    ret.chunksUrls = chunksUrls;

    return ret;
  }

  public serialize() {
    const ret: CollectionItemRevisionJsonWrite = {
      uid: this.uid,
      meta: sodium.to_base64(this.meta),
      deleted: this.deleted,

      chunks: this.chunks,
      chunksData: this.chunksData?.map((x) => sodium.to_base64(x)),
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
      cryptoMac.update(sodium.from_base64(chunk))
    );

    return cryptoMac.finalize();
  }

  public async decryptMeta(cryptoManager: CM, additionalData: Uint8Array[]): Promise<any> {
    const additionalDataMerged = additionalData.reduce((base, cur) => concatArrayBuffers(base, cur), new Uint8Array());
    return JSON.parse(sodium.to_string(cryptoManager.decrypt(this.meta, additionalDataMerged)));
  }

  public async decryptContent(cryptoManager: CM): Promise<Uint8Array> {
    return this.chunksData?.map((x, i) => cryptoManager.decryptDetached(x, sodium.from_base64(this.chunks[i])))
      .reduce((base, cur) => concatArrayBuffers(base, cur), new Uint8Array()) ?? new Uint8Array(0);
  }
}

export class EncryptedCollection {
  public uid: base62;
  public version: number;
  private encryptionKey: Uint8Array;
  private content: EncryptedRevision<CollectionCryptoManager>;

  public accessLevel: CollectionAccessLevel;
  public ctag: string | null;

  public static async create(parentCryptoManager: MainCryptoManager, meta: CollectionMetadata, content: Uint8Array): Promise<EncryptedCollection> {
    const ret = new EncryptedCollection();
    ret.uid = genUidBase62();
    ret.version = Constants.CURRENT_VERSION;
    ret.encryptionKey = parentCryptoManager.encrypt(sodium.crypto_aead_chacha20poly1305_ietf_keygen());

    ret.accessLevel = CollectionAccessLevel.Admin;
    ret.ctag = null;

    const cryptoManager = ret.getCryptoManager(parentCryptoManager);

    ret.content = await EncryptedRevision.create(cryptoManager, ret.getAdditionalMacData(), meta, content);

    return ret;
  }

  public static deserialize(json: CollectionJsonRead): EncryptedCollection {
    const { uid, ctag, version, accessLevel, encryptionKey, content } = json;
    const ret = new EncryptedCollection();
    ret.uid = uid;
    ret.version = version;
    ret.encryptionKey = sodium.from_base64(encryptionKey);

    ret.accessLevel = accessLevel;
    ret.ctag = ctag;

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

export class Account {
  private mainEncryptionKey: Uint8Array;
  private version: number;
  public authToken: string | null;

  private constructor(mainEncryptionKey: Uint8Array, version: number) {
    this.mainEncryptionKey = mainEncryptionKey;
    this.version = version;
    this.authToken = null;
  }

  public static async login(username: string, password: string, serverUrl?: string) {
    const authenticator = new Authenticator(serverUrl ?? Constants.SERVER_URL);

    // in reality these will be fetched:
    const salt = sodium.randombytes_buf(32);
    const version = 1;
    const ret = new this(salt, version);

    // FIXME: in reality, password would be derived from the encryption key
    const authToken = await authenticator.getAuthToken(username, password);
    ret.authToken = authToken

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

  constructor(etesync: Account) {
    this.etesync = etesync;
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

export class Authenticator extends BaseNetwork {
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

export class BaseManager extends BaseNetwork {
  protected credentials: Credentials;

  constructor(credentials: Credentials, apiBase: string, segments: string[]) {
    super(apiBase);
    this.credentials = credentials;
    this.apiBase = BaseNetwork.urlExtend(this.apiBase, ['api', 'v2'].concat(segments));
  }

  public newCall<T = any>(segments: string[] = [], extra: RequestInit = {}, apiBase: URI = this.apiBase): Promise<T> {
    extra = {
      ...extra,
      headers: {
        'Content-Type': 'application/json;charset=UTF-8',
        'Authorization': 'Token ' + this.credentials.authToken,
        ...extra.headers,
      },
    };

    return super.newCall(segments, extra, apiBase);
  }
}

export class CollectionManagerOnline extends BaseManager {
  constructor(credentials: Credentials, apiBase: string) {
    super(credentials, apiBase, ['collection']);
  }

  public fetch(colUid: string, syncToken: string | null): Promise<EncryptedCollection> {
    return new Promise((resolve, reject) => {
      this.newCall<CollectionJsonRead>([colUid]).then((json) => {
        const collection = EncryptedCollection.deserialize(json);
        resolve(collection);
      }).catch((error: Error) => {
        reject(error);
      });
    });
  }

  public list(syncToken: string | null, limit = 0): Promise<EncryptedCollection[]> {
    const apiBase = this.apiBase.clone().search({
      syncToken: (syncToken !== null) ? syncToken : undefined,
      limit: (limit > 0) ? limit : undefined,
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

  public update(collection: EncryptedCollection, syncToken: string | null): Promise<{}> {
    const extra = {
      method: 'put',
      body: JSON.stringify(collection.serialize()),
    };

    return this.newCall([collection.uid], extra);
  }

  public delete(collection: EncryptedCollection, syncToken: string | null): Promise<{}> {
    const extra = {
      method: 'delete',
    };

    return this.newCall([collection.uid], extra);
  }
}
