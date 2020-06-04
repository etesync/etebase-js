import URI from 'urijs';

import * as Constants from './Constants';

import { deriveKey, sodium, concatArrayBuffers, AsymmetricCryptoManager } from './Crypto';
export { deriveKey, ready } from './Crypto';
import { HTTPError, NetworkError } from './Exceptions';
export * from './Exceptions';
import { base62, base64, fromBase64, toBase64 } from './Helpers';
export { base62, base64, fromBase64, toBase64 } from './Helpers';

import {
  CollectionAccessLevel,
  CollectionCryptoManager,
  CollectionJsonRead,
  CollectionMetadata,
  CollectionItemJsonRead,
  CollectionItemMetadata,
  EncryptedCollection,
  EncryptedCollectionItem,
  getMainCryptoManager,
  SignedInvitationRead,
  SignedInvitationWrite,
} from './EncryptedModels';
export * from './EncryptedModels'; // FIXME: cherry-pick what we export

export { CURRENT_VERSION } from './Constants';

export interface ListResponse<T> {
  data: T[];
}

export interface CollectionItemListResponse<T> extends ListResponse<T> {
  stoken: string;
}

export interface CollectionListResponse<T> extends CollectionItemListResponse<T> {
  removedMemberships?: RemovedCollection[];
}

export interface RemovedCollection {
  uid: base62;
}

export interface CollectionMember {
  username: string;
  accessLevel: CollectionAccessLevel;
}

export interface AcceptedInvitation {
  encryptionKey: base64;
}

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

  public async upload(col: EncryptedCollection, options?: FetchOptions) {
    // If we have a etag, it means we previously fetched it.
    if (col.etag) {
      await this.onlineManager.update(col, options);
    } else {
      await this.onlineManager.create(col, options);
    }
    col.__markSaved();
  }

  public async transaction(col: EncryptedCollection, options?: FetchOptions) {
    // If we have a etag, it means we previously fetched it.
    if (col.etag) {
      await this.onlineManager.update(col, { ...options, stoken: col.stoken });
    } else {
      await this.onlineManager.create(col, { ...options, stoken: col.stoken });
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

  public async invite(col: EncryptedCollection, username: string, pubkey: base64, accessLevel: CollectionAccessLevel): Promise<void> {
    const mainCryptoManager = this.etesync.getCryptoManager();
    const identCryptoManager = this.etesync.getIdentityCryptoManager();
    const invitation = await col.createInvitation(mainCryptoManager, identCryptoManager, username, fromBase64(pubkey), accessLevel);
    await this.onlineManager.invite(invitation);
  }
}

export class CollectionMemberManager {
  private readonly etesync: Account;
  private readonly onlineManager: CollectionMemberManagerOnline;

  constructor(etesync: Account, _collectionManager: CollectionManager, col: EncryptedCollection) {
    this.etesync = etesync;
    this.onlineManager = new CollectionMemberManagerOnline(this.etesync, col);
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

export interface FetchOptions {
  stoken?: string | null;
  inline?: boolean;
  limit?: number;
}

export type ItemFetchOptions = FetchOptions;

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
}

export interface LoginResponseUser extends User {
  pubkey: base64;
  encryptedContent: base64;
}

export interface UserProfile {
  pubkey: base64;
}

export type LoginChallange = {
  username: string;
  challenge: string;
  salt: base64;
  version: number;
};

export type LoginChallangeResponse = {
  challenge: string;
  host: string;
};

export type LoginResponse = {
  token: string;
  user: LoginResponseUser;
};

class Authenticator extends BaseNetwork {
  constructor(apiBase: string) {
    super(apiBase);
    this.apiBase = BaseNetwork.urlExtend(this.apiBase, ['api', 'v1', 'authentication']);
  }

  public async signup(user: User, salt: Uint8Array, loginPubkey: Uint8Array, pubkey: Uint8Array, encryptedContent: Uint8Array): Promise<LoginResponse> {
    user = {
      username: user.username,
      email: user.email,
    };

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
        encryptedContent: toBase64(encryptedContent),
      }),
    };

    return this.newCall<LoginResponse>(['signup'], extra);
  }

  public getLoginChallenge(username: string): Promise<LoginChallange> {
    const extra = {
      method: 'post',
      headers: {
        'Content-Type': 'application/json;charset=UTF-8',
      },
      body: JSON.stringify({ username }),
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

  public async changePassword(authToken: string, loginPubkey: Uint8Array, encryptedContent: Uint8Array): Promise<void> {
    const extra = {
      method: 'post',
      headers: {
        'Content-Type': 'application/json;charset=UTF-8',
        'Authorization': 'Token ' + authToken,
      },
      body: JSON.stringify({
        loginPubkey: toBase64(loginPubkey),
        encryptedContent: toBase64(encryptedContent),
      }),
    };

    await this.newCall(['change_password'], extra);
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

    const { stoken, inline, limit } = options;

    if (!inline) {
      console.warn('inline must be set as the non-inline variant is not yet implemented.');
    }

    return this.apiBase.clone().search({
      stoken: (stoken !== null) ? stoken : undefined,
      limit: (limit && (limit > 0)) ? limit : undefined,
      inline: true,
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

  public async list(options: FetchOptions): Promise<CollectionListResponse<EncryptedCollection>> {
    const apiBase = this.urlFromFetchOptions(options);

    const json = await this.newCall<CollectionListResponse<CollectionJsonRead>>(undefined, undefined, apiBase);
    return {
      ...json,
      data: json.data.map((val) => EncryptedCollection.deserialize(val)),
    };
  }

  public create(collection: EncryptedCollection, options?: FetchOptions): Promise<{}> {
    const apiBase = this.urlFromFetchOptions(options);

    const extra = {
      method: 'post',
      body: JSON.stringify(collection.serialize()),
    };

    return this.newCall(undefined, extra, apiBase);
  }

  public update(collection: EncryptedCollection, options?: FetchOptions): Promise<{}> {
    const apiBase = this.urlFromFetchOptions(options);

    const extra = {
      method: 'put',
      body: JSON.stringify(collection.serialize()),
    };

    return this.newCall([collection.uid], extra, apiBase);
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

  public async list(options: ItemFetchOptions): Promise<CollectionItemListResponse<EncryptedCollectionItem>> {
    const apiBase = this.urlFromFetchOptions(options);

    const json = await this.newCall<CollectionItemListResponse<CollectionItemJsonRead>>(undefined, undefined, apiBase);
    return {
      ...json,
      data: json.data.map((val) => EncryptedCollectionItem.deserialize(val)),
    };
  }

  public create(item: EncryptedCollectionItem): Promise<{}> {
    const extra = {
      method: 'post',
      body: JSON.stringify(item.serialize()),
    };

    return this.newCall(undefined, extra);
  }

  public async fetchUpdates(items: EncryptedCollectionItem[], options?: ItemFetchOptions): Promise<CollectionItemListResponse<EncryptedCollectionItem>> {
    const apiBase = this.urlFromFetchOptions(options);
    // We only use stoken if available
    const wantEtag = !options?.stoken;

    const extra = {
      method: 'post',
      body: JSON.stringify(items?.map((x) => ({ uid: x.uid, etag: ((wantEtag) ? x.etag : undefined) }))),
    };

    const json = await this.newCall<CollectionItemListResponse<CollectionItemJsonRead>>(['fetch_updates'], extra, apiBase);
    const data = json.data;
    return {
      ...json,
      data: data.map((val) => EncryptedCollectionItem.deserialize(val)),
    };
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
        deps: deps?.map((x) => ({ uid: x.uid, etag: x.etag })),
      }),
    };

    return this.newCall(['transaction'], extra, apiBase);
  }
}

class CollectionInvitationManagerOnline extends BaseManager {
  constructor(etesync: Account) {
    super(etesync, ['invitation']);
  }

  public async listIncoming(): Promise<ListResponse<SignedInvitationRead>> {
    const json = await this.newCall<ListResponse<SignedInvitationRead>>(['incoming']);
    return {
      ...json,
      data: json.data.map((val) => val),
    };
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

class CollectionMemberManagerOnline extends BaseManager {
  constructor(etesync: Account, col: EncryptedCollection) {
    super(etesync, ['collection', col.uid, 'member']);
  }

  public async list(): Promise<ListResponse<CollectionMember>> {
    return this.newCall<ListResponse<CollectionMember>>();
  }

  public async remove(username: string): Promise<{}> {
    const extra = {
      method: 'delete',
    };

    return this.newCall([username], extra);
  }

  public async leave(): Promise<{}> {
    const extra = {
      method: 'post',
    };

    return this.newCall(['leave'], extra);
  }

  public async modifyAccessLevel(username: string, accessLevel: CollectionAccessLevel): Promise<{}> {
    const extra = {
      method: 'patch',
      body: JSON.stringify({
        accessLevel,
      }),
    };

    return this.newCall([username], extra);
  }
}
