import sjcl from 'sjcl';
import URI from 'urijs';

import * as Constants from './Constants';

import { byte, base64, stringToByteArray } from './Helpers';
import { CryptoManager, AsymmetricCryptoManager, AsymmetricKeyPair, HMAC_SIZE_BYTES } from './Crypto';
export { CryptoManager, AsymmetricCryptoManager, AsymmetricKeyPair, deriveKey, genUid } from './Crypto';
export { byte, base64 } from './Helpers';

export { CURRENT_VERSION } from './Constants';

type URI = typeof URI;

class ExtendableError extends Error {
  constructor(message: any) {
    super(message);
    Object.setPrototypeOf(this, ExtendableError.prototype);
    this.name = this.constructor.name;
    this.stack = (new Error(message)).stack;
  }
}

export class HTTPError extends ExtendableError {
  constructor(message: any) {
    super(message);
    Object.setPrototypeOf(this, HTTPError.prototype);
    this.name = this.constructor.name;
  }
}

export class IntegrityError extends ExtendableError {
  constructor(message: any) {
    super(message);
    Object.setPrototypeOf(this, IntegrityError.prototype);
    this.name = this.constructor.name;
  }
}

export class EncryptionPasswordError extends ExtendableError {
  constructor(message: any) {
    super(message);
    Object.setPrototypeOf(this, EncryptionPasswordError.prototype);
    this.name = this.constructor.name;
  }
}

// FIXME: Make secure + types
function CastJson(json: any, to: any) {
  return Object.assign(to, json);
}

function hmacToHex(hmac: byte[]): string {
  return sjcl.codec.hex.fromBits(sjcl.codec.bytes.toBits(hmac));
}

export class Credentials {
  public email: string;
  public authToken: string;

  constructor(email: string, authToken: string) {
    this.email = email;
    this.authToken = authToken;
  }
}

export class CollectionInfo {
  public uid: string;
  public type: string;
  public displayName: string;
  public description: string;
  public color: number;

  constructor(json?: any) {
    CastJson(json, this);
  }
}

interface BaseItemJson {
  content: base64;
}

class BaseItem<T extends BaseItemJson> {
  protected _json: T;
  protected _encrypted: byte[];
  protected _content?: object;

  constructor() {
    this._json = {} as T;
  }

  public deserialize(json: T) {
    this._json = Object.assign({}, json);
    if (json.content) {
      this._encrypted = sjcl.codec.bytes.fromBits(sjcl.codec.base64.toBits(json.content));
    }
    this._content = undefined;
  }

  public serialize(): T {
    return Object.assign(
      {},
      this._json,
      { content: sjcl.codec.base64.fromBits(sjcl.codec.bytes.toBits(this._encrypted)) }
    );
  }

  protected verifyBase(hmac: byte[], calculated: byte[]) {
    if (!this.hmacEqual(hmac, calculated)) {
      throw new IntegrityError('Bad HMAC. ' + hmacToHex(hmac) + ' != ' + hmacToHex(calculated));
    }
  }

  private hmacEqual(hmac: byte[], calculated: byte[]) {
    return (hmac.length === calculated.length) &&
      (hmac.every((v, i) => v === calculated[i]));
  }
}

interface BaseJson extends BaseItemJson {
  uid: string;
}

class BaseJournal<T extends BaseJson> extends BaseItem<T> {
  get uid(): string {
    return this._json.uid;
  }
}

export interface JournalJson extends BaseJson {
  version: number;
  owner: string;
  readOnly?: boolean;
  key?: base64;
}

export class Journal extends BaseJournal<JournalJson> {
  constructor(initial?: Partial<JournalJson>, version: number = Constants.CURRENT_VERSION) {
    super();
    this._json = {
      ...this._json,
      version,
      ...initial,
    };
  }

  get key(): byte[] | undefined {
    if (this._json.key) {
      return sjcl.codec.bytes.fromBits(sjcl.codec.base64.toBits(this._json.key));
    }

    return undefined;
  }

  get owner(): string | undefined {
    return this._json.owner;
  }

  get readOnly(): boolean | undefined {
    return this._json.readOnly;
  }

  get version(): number {
    return this._json.version;
  }

  public getCryptoManager(derived: string, keyPair: AsymmetricKeyPair) {
    if (this.key) {
      const asymmetricCryptoManager = new AsymmetricCryptoManager(keyPair);
      const derivedJournalKey = asymmetricCryptoManager.decryptBytes(this.key);
      return CryptoManager.fromDerivedKey(derivedJournalKey, this.version);
    } else {
      return new CryptoManager(derived, this.uid, this.version);
    }
  }

  public setInfo(cryptoManager: CryptoManager, info: CollectionInfo) {
    this._json.uid = info.uid;
    this._content = info;
    const encrypted = cryptoManager.encrypt(JSON.stringify(this._content));
    this._encrypted = this.calculateHmac(cryptoManager, encrypted).concat(encrypted);
  }

  public getInfo(cryptoManager: CryptoManager): CollectionInfo {
    this.verify(cryptoManager);

    if (this._content === undefined) {
      this._content = JSON.parse(cryptoManager.decrypt(this.encryptedContent()));
    }

    const ret = new CollectionInfo(this._content);
    ret.uid = this.uid;
    return ret;
  }

  public calculateHmac(cryptoManager: CryptoManager, encrypted: byte[]): byte[] {
    const prefix = stringToByteArray(this.uid);
    return cryptoManager.hmac(prefix.concat(encrypted));
  }

  public verify(cryptoManager: CryptoManager) {
    const calculated = this.calculateHmac(cryptoManager, this.encryptedContent());
    const hmac = this._encrypted.slice(0, HMAC_SIZE_BYTES);

    super.verifyBase(hmac, calculated);
  }

  private encryptedContent(): byte[] {
    return this._encrypted.slice(HMAC_SIZE_BYTES);
  }
}

export enum SyncEntryAction {
  Add = 'ADD',
  Delete = 'DELETE',
  Change = 'CHANGE',
}

export class SyncEntry {
  public uid?: string;
  public action: SyncEntryAction;
  public content: string;

  constructor(json?: any, uid?: string) {
    CastJson(json, this);
    this.uid = uid;
  }
}

export type EntryJson = BaseJson;

export class Entry extends BaseJournal<EntryJson> {
  public setSyncEntry(cryptoManager: CryptoManager, info: SyncEntry, prevUid: string | null) {
    this._content = info;
    this._encrypted = cryptoManager.encrypt(JSON.stringify(this._content));
    this._json.uid = hmacToHex(this.calculateHmac(cryptoManager, this._encrypted, prevUid));
  }

  public getSyncEntry(cryptoManager: CryptoManager, prevUid: string | null): SyncEntry {
    this.verify(cryptoManager, prevUid);

    if (this._content === undefined) {
      this._content = JSON.parse(cryptoManager.decrypt(this._encrypted));
    }

    return new SyncEntry(this._content, this.uid);
  }

  public verify(cryptoManager: CryptoManager, prevUid: string | null) {
    const calculated = this.calculateHmac(cryptoManager, this._encrypted, prevUid);
    const hmac = sjcl.codec.bytes.fromBits(sjcl.codec.hex.toBits(this.uid));

    super.verifyBase(hmac, calculated);
  }

  private calculateHmac(cryptoManager: CryptoManager, encrypted: byte[], prevUid: string | null): byte[] {
    const prefix = (prevUid !== null) ? stringToByteArray(prevUid) : [];
    return cryptoManager.hmac(prefix.concat(encrypted));
  }
}

export interface UserInfoJson extends BaseItemJson {
  version?: number;
  owner?: string;
  pubkey: base64;
}

export class UserInfo extends BaseItem<UserInfoJson> {
  public _owner: string;

  constructor(owner: string, version: number = Constants.CURRENT_VERSION) {
    super();
    this._json.version = version;
    this._owner = owner;
  }

  get version(): number {
    return this._json.version!;
  }

  get owner(): string {
    return this._owner;
  }

  get publicKey() {
    return this._json.pubkey;
  }

  public serialize(): UserInfoJson {
    const ret = super.serialize();
    ret.owner = this._owner;
    return ret;
  }

  public getCryptoManager(derived: string) {
    return new CryptoManager(derived, 'userInfo', this.version);
  }

  public setKeyPair(cryptoManager: CryptoManager, keyPair: AsymmetricKeyPair) {
    this._json.pubkey = sjcl.codec.base64.fromBits(sjcl.codec.bytes.toBits(keyPair.publicKey));
    this._content = keyPair.privateKey;
    const encrypted = cryptoManager.encryptBytes(keyPair.privateKey);
    this._encrypted = this.calculateHmac(cryptoManager, encrypted).concat(encrypted);
  }

  public getKeyPair(cryptoManager: CryptoManager): AsymmetricKeyPair {
    this.verify(cryptoManager);

    if (this._content === undefined) {
      this._content = cryptoManager.decryptBytes(this.encryptedContent());
    }

    const pubkey = sjcl.codec.bytes.fromBits(sjcl.codec.base64.toBits(this._json.pubkey));
    return new AsymmetricKeyPair(pubkey, this._content as byte[]);
  }

  public calculateHmac(cryptoManager: CryptoManager, encrypted: byte[]): byte[] {
    const postfix = sjcl.codec.bytes.fromBits(sjcl.codec.base64.toBits(this._json.pubkey));
    return cryptoManager.hmac(encrypted.concat(postfix));
  }

  public verify(cryptoManager: CryptoManager) {
    const calculated = this.calculateHmac(cryptoManager, this.encryptedContent());
    const hmac = this._encrypted.slice(0, HMAC_SIZE_BYTES);

    super.verifyBase(hmac, calculated);
  }

  private encryptedContent(): byte[] {
    return this._encrypted.slice(HMAC_SIZE_BYTES);
  }
}

// FIXME: baseUrl and apiBase should be the right type all around.

class BaseNetwork {

  public static urlExtend(_baseUrl: URI, segments: string[]): URI {
    let baseUrl = _baseUrl as any;
    baseUrl = baseUrl.clone();
    for (const segment of segments) {
      baseUrl.segment(segment);
    }
    return baseUrl.normalize();
  }
  public apiBase: any; // FIXME

  constructor(apiBase: string) {
    this.apiBase = URI(apiBase).normalize();
  }

  public newCall<T = any>(segments: string[] = [], extra: RequestInit = {}, _apiBase: URI = this.apiBase): Promise<T> {
    const apiBase = BaseNetwork.urlExtend(_apiBase, segments);

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
              reject(new HTTPError(json.detail || json.non_field_errors || JSON.stringify(json)));
            } else {
              reject(new HTTPError(body));
            }
          }
        }).catch((error) => {
          reject(error);
        });
      }).catch((error) => {
        reject(error);
      });
    });
  }
}

export class Authenticator extends BaseNetwork {
  constructor(apiBase: string) {
    super(apiBase);
    this.apiBase = BaseNetwork.urlExtend(this.apiBase, ['api-token-auth', '']);
  }

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

      this.newCall<{token: string}>([], extra).then((json) => {
        resolve(json.token);
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
    this.apiBase = BaseNetwork.urlExtend(this.apiBase, ['api', 'v1'].concat(segments));
  }

  public newCall<T = any>(segments: string[] = [], extra: RequestInit = {}, apiBase: any = this.apiBase): Promise<T> {
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

export class JournalManager extends BaseManager {
  constructor(credentials: Credentials, apiBase: string) {
    super(credentials, apiBase, ['journals', '']);
  }

  public fetch(journalUid: string): Promise<Journal> {
    return new Promise((resolve, reject) => {
      this.newCall<JournalJson>([journalUid, '']).then((json) => {
        const journal = new Journal({ uid: json.uid }, json.version);
        journal.deserialize(json);
        resolve(journal);
      }).catch((error: Error) => {
        reject(error);
      });
    });
  }

  public list(): Promise<Journal[]> {
    return new Promise((resolve, reject) => {
      this.newCall<JournalJson[]>().then((json) => {
        resolve(json.map((val: JournalJson) => {
          const journal = new Journal({ uid: val.uid }, val.version);
          journal.deserialize(val);
          return journal;
        }));
      }).catch((error: Error) => {
        reject(error);
      });
    });
  }

  public create(journal: Journal): Promise<{}> {
    const extra = {
      method: 'post',
      body: JSON.stringify(journal.serialize()),
    };

    return this.newCall<Journal>([], extra);
  }

  public update(journal: Journal): Promise<{}> {
    const extra = {
      method: 'put',
      body: JSON.stringify(journal.serialize()),
    };

    return this.newCall<Journal>([journal.uid, ''], extra);
  }

  public delete(journal: Journal): Promise<{}> {
    const extra = {
      method: 'delete',
    };

    return this.newCall([journal.uid, ''], extra);
  }
}

export class EntryManager extends BaseManager {
  constructor(credentials: Credentials, apiBase: string, journalId: string) {
    super(credentials, apiBase, ['journals', journalId, 'entries', '']);
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
  key: base64;
  readOnly?: boolean;
}

export class JournalMembersManager extends BaseManager {
  constructor(credentials: Credentials, apiBase: string, journalId: string) {
    super(credentials, apiBase, ['journals', journalId, 'members', '']);
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

    return this.newCall([], extra);
  }

  public delete(journalMember: JournalMemberJson): Promise<{}> {
    const extra = {
      method: 'delete',
    };

    return this.newCall([journalMember.user, ''], extra);
  }
}

export class UserInfoManager extends BaseManager {
  constructor(credentials: Credentials, apiBase: string) {
    super(credentials, apiBase, ['user', '']);
  }

  public fetch(owner: string): Promise<UserInfo> {
    return new Promise((resolve, reject) => {
      this.newCall<UserInfoJson>([owner, '']).then((json) => {
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

    return this.newCall([], extra);
  }

  public update(userInfo: UserInfo): Promise<{}> {
    const extra = {
      method: 'put',
      body: JSON.stringify(userInfo.serialize()),
    };

    return this.newCall([userInfo.owner, ''], extra);
  }

  public delete(userInfo: UserInfo): Promise<{}> {
    const extra = {
      method: 'delete',
    };

    return this.newCall([userInfo.owner, ''], extra);
  }
}
