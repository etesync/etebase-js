import URI from 'urijs';

import * as Constants from './Constants';

import { CryptoManager, sodium } from './Crypto';
export { deriveKey, ready } from './Crypto';
import { HTTPError, NetworkError, IntegrityError } from './Exceptions';
export * from './Exceptions';
import { base62, base64url } from './Helpers';
export { base62, base64url } from './Helpers';

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

export class CollectionItemRevisionBla<CM extends CollectionCryptoManager | CollectionItemCryptoManager> {
  public uid: base64url;
  public chunks: base64url[];
  public deleted: boolean;
  public meta: Uint8Array | null;
  public chunksUrls?: string[];
  public chunksData?: Uint8Array[];

  public static deserialize(json: CollectionItemRevisionJsonRead) {
    const ret = new this();
    ret.uid = json.uid;
    ret.chunks = json.chunks;
    ret.deleted = json.deleted;
    ret.meta = (json.meta) ? sodium.from_base64(json.meta) : null;
    ret.chunksUrls = json.chunksUrls;
    ret.chunksData = json.chunksData?.map((x) => sodium.from_base64(x));
    return ret;
  }

  public serialize() {
    const ret: CollectionItemRevisionJsonWrite = {
      deleted: this.deleted,
      chunks: this.chunks,
      uid: this.uid,
      meta: (this.meta) ? sodium.to_base64(this.meta) : null,
    };
    return ret;
  }

  public static create<M extends {}, CM extends CollectionCryptoManager | CollectionItemCryptoManager>(
    cryptoManager: CM, additionalDataMac: Uint8Array[] = [],
    content: CollectionItemRevisionContent<M>) {

    const ret = new this();
    ret.chunks = content?.chunks ?? [];
    ret.deleted = content?.deleted ?? false;
    ret.meta = (content.meta) ?
      cryptoManager.encrypt(sodium.from_string(JSON.stringify(content.meta))) :
      null;
    ret.uid = sodium.to_base64(ret.calculateMac(cryptoManager, additionalDataMac));
    return ret;
  }

  public verify(cryptoManager: CM, additionalData: Uint8Array[] = []) {
    const calculatedMac = this.calculateMac(cryptoManager, additionalData);
    if (sodium.memcmp(
      sodium.from_base64(this.uid),
      calculatedMac
    )) {
      return true;
    } else {
      throw new IntegrityError(`mac verification failed. Expected: ${this.uid} got: ${sodium.to_base64(calculatedMac)}`);
    }
  }

  public calculateMac(cryptoManager: CM, additionalData: Uint8Array[] = []) {
    const cryptoMac = cryptoManager.getCryptoMac();
    cryptoMac.update(Uint8Array.from([(this.deleted) ? 1 : 0]));
    this.chunks.forEach((chunk) =>
      cryptoMac.update(sodium.from_base64(chunk))
    );
    if (this.meta) {
      // the tag is appended to the message
      cryptoMac.update(this.meta.subarray(-1 * sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES));
    }
    additionalData.forEach((data) =>
      cryptoMac.update(data)
    );

    return cryptoMac.finalize();
  }

  public decryptMeta(cryptoManager: CM): any | null {
    if (this.meta) {
      return JSON.parse(sodium.to_string(cryptoManager.decrypt(this.meta)));
    } else {
      return null;
    }
  }
}

class CollectionItemRevision<M extends {}> {
  public deleted = false;

  private _decrypted: {
    meta?: M;
    content?: ContentType;
  } = {};
  private _changed = {
    meta: false,
    content: false,
  };

  constructor(
    data: {
      meta?: M;
      content?: ContentType;
    }
  ) {

    if (data.meta) {
      this.setMeta(data.meta);
    }
    if (data.content) {
      this.setContent(data.content);
    }
  }

  protected setMeta(meta: M) {
    this._decrypted.meta = meta;

    this._changed.meta = true;
  }

  public getMeta(_collectionManager: CollectionManager) {
    return this._decrypted.meta;
  }

  protected setContent(content: ContentType) {
    this._decrypted.content = content;

    this._changed.content = true;
  }

  public getContent(_collectionManager: CollectionManager) {
    return this._decrypted.content;
  }

  public get changed(): boolean {
    return this._changed.content || this._changed.meta;
  }

  public set changed(changed: boolean) {
    this._changed.content = changed;
    this._changed.meta = changed;
  }

  public remove() {
    this.deleted = true;

    return this;
  }
}

export class Collection<M extends CollectionMetadata> {
  protected encryptedEncryptionKey: Uint8Array;

  public readonly accessLevel: CollectionAccessLevel;
  public ctag: string | null = null;

  private content: CollectionItemRevision<M>;
  private remoteContent: CollectionItemRevisionJsonRead; // This is how we got it when we deserailezd so we can hold data needed for comparison of content

  constructor(
    readonly uid = Collection.genUid(),
    readonly version = Constants.CURRENT_VERSION,
    data: {
      meta?: M;
      content?: ContentType;
      accessLevel?: CollectionAccessLevel;
    }
  ) {
    this.accessLevel = data.accessLevel ?? CollectionAccessLevel.Admin;

    this.content = new CollectionItemRevision(data);
  }

  public static genUid() {
    const rand = sodium.randombytes_buf(24);
    // We only want alphanumeric and we don't care about the bias
    return sodium.to_base64(rand).replace('-', 'a').replace('_', 'b');
  }

  public static deserialize(json: CollectionJsonRead) {
    const ret = new this(json.uid, json.version, {
      accessLevel: json.accessLevel,
    });
    ret.content.deserializeInner(json);
    ret.encryptedEncryptionKey = sodium.from_base64(json.encryptionKey);


    ret.ctag = json.ctag;

    return ret;
  }

  public serialize(collectionManager: CollectionManager) {
    const ret: CollectionJsonWrite = {
      uid: this.uid,
      version: this.version,

      encryptionKey: sodium.to_base64(this.encryptedEncryptionKey),
      content: this.content.serialize(),
    };
    return ret;
  }

}

export class EteSync {
  private mainEncryptionKey: Uint8Array;
  private version: number;

  private constructor(mainEncryptionKey: Uint8Array, version: number) {
    this.mainEncryptionKey = mainEncryptionKey;
    this.version = version;
  }

  public static login(_username: string, _password: string, _serverUrl?: string) {
    // in reality these will be fetched:
    const salt = sodium.randombytes_buf(32);
    const version = 1;
    return new this(salt, version);
  }

  public getCollectionManager() {
    return new CollectionManager(this);
  }

  public getCryptoManager() {
    return new MainCryptoManager(this.mainEncryptionKey, this.version);
  }
}

export class CollectionManager {
  private readonly etesync: EteSync;

  constructor(etesync: EteSync) {
    this.etesync = etesync;
  }

  public verify(cryptoManager: CollectionCryptoManager) {
    return this.content.verify(cryptoManager, this.getAdditionalMacData());
  }

  public decryptMeta(cryptoManager: CollectionCryptoManager): CollectionMetadata | null {
    return this.content.decryptMeta(cryptoManager);
  }

  public getCryptoManager(parentCryptoManager: MainCryptoManager, col: Collection<any>) {
    const encryptionKey = parentCryptoManager.decrypt(col.encryptedEncryptionKey);

    return new CollectionCryptoManager(encryptionKey, col.version);
  }

  protected getAdditionalMacData(col: Collection) {
    return [sodium.from_string(col.uid)];
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

  public fetch(colUid: string, syncToken: string | null): Promise<Collection> {
    return new Promise((resolve, reject) => {
      this.newCall<CollectionJsonRead>([colUid]).then((json) => {
        const collection = Collection.deserialize(json);
        resolve(collection);
      }).catch((error: Error) => {
        reject(error);
      });
    });
  }

  public list(syncToken: string | null, limit = 0): Promise<Collection[]> {
    const apiBase = this.apiBase.clone().search({
      syncToken: (syncToken !== null) ? syncToken : undefined,
      limit: (limit > 0) ? limit : undefined,
    });

    return new Promise((resolve, reject) => {
      this.newCall<CollectionJsonRead[]>(undefined, undefined, apiBase).then((json) => {
        resolve(json.map((val) => {
          const collection = Collection.deserialize(val);
          return collection;
        }));
      }).catch((error: Error) => {
        reject(error);
      });
    });
  }

  public create(collection: Collection): Promise<{}> {
    const extra = {
      method: 'post',
      body: JSON.stringify(collection.serialize()),
    };

    return this.newCall(undefined, extra);
  }

  public update(collection: Collection, syncToken: string | null): Promise<{}> {
    const extra = {
      method: 'put',
      body: JSON.stringify(collection.serialize()),
    };

    return this.newCall<Collection>([collection.uid], extra);
  }

  public delete(collection: Collection, syncToken: string | null): Promise<{}> {
    const extra = {
      method: 'delete',
    };

    return this.newCall([collection.uid], extra);
  }
}

export class EntryManager extends BaseManager {
  constructor(credentials: Credentials, apiBase: string, journalId: string) {
    super(credentials, apiBase, ['journals', journalId, 'entries']);
  }

  public list(lastUid: string | null, limit = 0): Promise<Entry[]> {
    let apiBase = this.apiBase.clone();
    apiBase = apiBase.search({
      last: (lastUid !== null) ? lastUid : undefined,
      limit: (limit > 0) ? limit : undefined,
    });

    return new Promise((resolve, reject) => {
      this.newCall<EntryJson[]>(undefined, undefined, apiBase).then((json) => {
        resolve(json.map((val) => {
          const entry = new Entry();
          entry.deserialize(val);
          return entry;
        }));
      }).catch((error: Error) => {
        reject(error);
      });
    });
  }

  public create(entries: Entry[], lastUid: string | null): Promise<{}> {
    let apiBase = this.apiBase.clone();
    apiBase = apiBase.search({
      last: (lastUid !== null) ? lastUid : undefined,
    });

    const extra = {
      method: 'post',
      body: JSON.stringify(entries.map((x) => x.serialize())),
    };

    return this.newCall(undefined, extra, apiBase);
  }
}

export interface JournalMemberJson {
  user: string;
  key: base64url;
  readOnly?: boolean;
}

export class JournalMembersManager extends BaseManager {
  constructor(credentials: Credentials, apiBase: string, journalId: string) {
    super(credentials, apiBase, ['journals', journalId, 'members']);
  }

  public list(): Promise<JournalMemberJson[]> {
    return new Promise((resolve, reject) => {
      this.newCall<JournalMemberJson[]>().then((json) => {
        resolve(json.map((val) => {
          return val;
        }));
      }).catch((error: Error) => {
        reject(error);
      });
    });
  }

  public create(journalMember: JournalMemberJson): Promise<{}> {
    const extra = {
      method: 'post',
      body: JSON.stringify(journalMember),
    };

    return this.newCall(undefined, extra);
  }

  public delete(journalMember: JournalMemberJson): Promise<{}> {
    const extra = {
      method: 'delete',
    };

    return this.newCall([journalMember.user], extra);
  }
}

export class UserInfoManager extends BaseManager {
  constructor(credentials: Credentials, apiBase: string) {
    super(credentials, apiBase, ['user']);
  }

  public fetch(owner: string): Promise<UserInfo> {
    return new Promise((resolve, reject) => {
      this.newCall<UserInfoJson>([owner]).then((json) => {
        const userInfo = new UserInfo(owner, json.version);
        userInfo.deserialize(json);
        resolve(userInfo);
      }).catch((error: Error) => {
        reject(error);
      });
    });
  }

  public create(userInfo: UserInfo): Promise<{}> {
    const extra = {
      method: 'post',
      body: JSON.stringify(userInfo.serialize()),
    };

    return this.newCall(undefined, extra);
  }

  public update(userInfo: UserInfo): Promise<{}> {
    const extra = {
      method: 'put',
      body: JSON.stringify(userInfo.serialize()),
    };

    return this.newCall([userInfo.owner], extra);
  }

  public delete(userInfo: UserInfo): Promise<{}> {
    const extra = {
      method: 'delete',
    };

    return this.newCall([userInfo.owner], extra);
  }
}
