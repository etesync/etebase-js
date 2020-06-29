import request from "./Request";

import URI from "urijs";

export { deriveKey, ready } from "./Crypto";
import { HTTPError, NetworkError, EncryptionPasswordError } from "./Exceptions";
export * from "./Exceptions";
import { base64, msgpackEncode, msgpackDecode, toBase64, toString } from "./Helpers";

import {
  CollectionAccessLevel,
  CollectionJsonRead,
  CollectionItemJsonRead,
  EncryptedCollection,
  EncryptedCollectionItem,
  SignedInvitationRead,
  SignedInvitationWrite,
  CollectionItemRevisionJsonRead,
} from "./EncryptedModels";

export interface User {
  username: string;
  email: string;
}

export interface LoginResponseUser extends User {
  pubkey: Uint8Array;
  encryptedContent: Uint8Array;
}

export interface UserProfile {
  pubkey: Uint8Array;
}

export type LoginChallange = {
  username: string;
  challenge: string;
  salt: Uint8Array;
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

export interface ListResponse<T> {
  data: T[];
  done: boolean;
}

export interface CollectionItemListResponse<T> extends ListResponse<T> {
  stoken: string;
}

export interface CollectionListResponse<T> extends CollectionItemListResponse<T> {
  removedMemberships?: RemovedCollection[];
}

export interface IteratorListResponse<T> extends ListResponse<T> {
  iterator: string;
}

export type CollectionMemberListResponse<T> = IteratorListResponse<T>;

export type CollectionInvitationListResponse<T> = IteratorListResponse<T>;

export interface RemovedCollection {
  uid: base64;
}

export interface CollectionMember {
  username: string;
  accessLevel: CollectionAccessLevel;
}

export interface AcceptedInvitation {
  encryptionKey: Uint8Array;
}

export interface ListFetchOptions {
  limit?: number;
}

export interface FetchOptions extends ListFetchOptions {
  stoken?: string | null;
  prefetch?: boolean;
}

export interface ItemFetchOptions extends FetchOptions {
  withCollection?: boolean;
}

export interface IteratorFetchOptions extends ListFetchOptions {
  iterator?: string | null;
}

export type MemberFetchOptions = IteratorFetchOptions;

export type InvitationFetchOptions = IteratorFetchOptions;

export interface RevisionsFetchOptions extends IteratorFetchOptions {
  prefetch?: boolean;
}

interface AccountOnlineData {
  serverUrl: string;
  authToken: string | null;
}

class BaseNetwork {

  public static urlExtend(baseUrlIn: URI, segments: string[]): URI {
    const baseUrl = baseUrlIn.clone();
    for (const segment of segments) {
      baseUrl.segment(segment);
    }
    baseUrl.segment("");
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
        Accept: "application/msgpack",
        ...extra.headers,
      },
    };

    let response;
    try {
      response = await request(apiBase.toString(), extra);
    } catch (e) {
      throw new NetworkError(e.message);
    }

    const body = response.body;
    let data: any;
    let bodyStr;
    try {
      data = msgpackDecode(body);
    } catch (e) {
      const uintbody = new Uint8Array(body);
      try {
        bodyStr = toString(uintbody);
        // Try falling back to json (e.g. in case the server errored in json)
        data = JSON.parse(data);
      } catch (e) {
        bodyStr = bodyStr ?? toBase64(uintbody);
      }
    }

    if (response.ok) {
      return data;
    } else {
      if (data) {
        throw new HTTPError(response.status, data.detail || data.non_field_errors || JSON.stringify(data), data);
      } else {
        throw new HTTPError(response.status, bodyStr);
      }
    }
  }
}

export class Authenticator extends BaseNetwork {
  constructor(apiBase: string) {
    super(apiBase);
    this.apiBase = BaseNetwork.urlExtend(this.apiBase, ["api", "v1", "authentication"]);
  }

  public async newCall<T = any>(segments: string[] = [], extra: RequestInit = {}, apiBase: URI = this.apiBase): Promise<T> {
    try {
      return await super.newCall(segments, extra, apiBase);
    } catch (e) {
      if (e instanceof HTTPError) {
        if (e.content?.code === "login_bad_signature") {
          throw new EncryptionPasswordError(e.content.detail || e.message);
        }
      }
      throw e;
    }
  }

  public async signup(user: User, salt: Uint8Array, loginPubkey: Uint8Array, pubkey: Uint8Array, encryptedContent: Uint8Array): Promise<LoginResponse> {
    user = {
      username: user.username,
      email: user.email,
    };

    const extra = {
      method: "post",
      headers: {
        "Content-Type": "application/msgpack",
      },
      body: msgpackEncode({
        user,
        salt: salt,
        loginPubkey: loginPubkey,
        pubkey: pubkey,
        encryptedContent: encryptedContent,
      }),
    };

    return this.newCall<LoginResponse>(["signup"], extra);
  }

  public getLoginChallenge(username: string): Promise<LoginChallange> {
    const extra = {
      method: "post",
      headers: {
        "Content-Type": "application/msgpack",
      },
      body: msgpackEncode({ username }),
    };

    return this.newCall<LoginChallange>(["login_challenge"], extra);
  }

  public login(response: Uint8Array, signature: Uint8Array): Promise<LoginResponse> {
    const extra = {
      method: "post",
      headers: {
        "Content-Type": "application/msgpack",
      },
      body: msgpackEncode({
        response: response,
        signature: signature,
      }),
    };

    return this.newCall<LoginResponse>(["login"], extra);
  }

  public logout(authToken: string): Promise<void> {
    const extra = {
      method: "post",
      headers: {
        "Content-Type": "application/msgpack",
        "Authorization": "Token " + authToken,
      },
    };

    return this.newCall(["logout"], extra);
  }

  public async changePassword(authToken: string, response: Uint8Array, signature: Uint8Array): Promise<void> {
    const extra = {
      method: "post",
      headers: {
        "Content-Type": "application/msgpack",
        "Authorization": "Token " + authToken,
      },
      body: msgpackEncode({
        response: response,
        signature: signature,
      }),
    };

    await this.newCall(["change_password"], extra);
  }
}

class BaseManager extends BaseNetwork {
  protected etebase: AccountOnlineData;

  constructor(etebase: AccountOnlineData, segments: string[]) {
    super(etebase.serverUrl);
    this.etebase = etebase;
    this.apiBase = BaseNetwork.urlExtend(this.apiBase, ["api", "v1"].concat(segments));
  }

  public newCall<T = any>(segments: string[] = [], extra: RequestInit = {}, apiBase: URI = this.apiBase): Promise<T> {
    extra = {
      ...extra,
      headers: {
        "Content-Type": "application/msgpack",
        "Authorization": "Token " + this.etebase.authToken,
        ...extra.headers,
      },
    };

    return super.newCall(segments, extra, apiBase);
  }

  protected urlFromFetchOptions(options?: ItemFetchOptions & IteratorFetchOptions) {
    if (!options) {
      return this.apiBase;
    }

    const { stoken, prefetch, limit, withCollection, iterator } = options;

    return this.apiBase.clone().search({
      stoken: (stoken !== null) ? stoken : undefined,
      iterator: (iterator !== null) ? iterator : undefined,
      limit: (limit && (limit > 0)) ? limit : undefined,
      withCollection: withCollection,
      prefetch,
    });
  }
}

export class CollectionManagerOnline extends BaseManager {
  constructor(etebase: AccountOnlineData) {
    super(etebase, ["collection"]);
  }

  public async fetch(colUid: string, options?: FetchOptions): Promise<EncryptedCollection> {
    const apiBase = this.urlFromFetchOptions(options);

    const json = await this.newCall<CollectionJsonRead>([colUid], undefined, apiBase);
    return EncryptedCollection.deserialize(json);
  }

  public async list(options?: FetchOptions): Promise<CollectionListResponse<EncryptedCollection>> {
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
      method: "post",
      body: msgpackEncode(collection.serialize()),
    };

    return this.newCall(undefined, extra, apiBase);
  }
}

export class CollectionItemManagerOnline extends BaseManager {
  constructor(etebase: AccountOnlineData, col: EncryptedCollection) {
    super(etebase, ["collection", col.uid, "item"]);
  }

  public async fetch(itemUid: string, options?: ItemFetchOptions): Promise<EncryptedCollectionItem> {
    const apiBase = this.urlFromFetchOptions(options);

    const json = await this.newCall<CollectionItemJsonRead>([itemUid], undefined, apiBase);
    return EncryptedCollectionItem.deserialize(json);
  }

  public async list(options?: ItemFetchOptions): Promise<CollectionItemListResponse<EncryptedCollectionItem>> {
    const apiBase = this.urlFromFetchOptions(options);

    const json = await this.newCall<CollectionItemListResponse<CollectionItemJsonRead>>(undefined, undefined, apiBase);
    return {
      ...json,
      data: json.data.map((val) => EncryptedCollectionItem.deserialize(val)),
    };
  }

  public async itemRevisions(item: EncryptedCollectionItem, options?: RevisionsFetchOptions): Promise<IteratorListResponse<EncryptedCollectionItem>> {
    const apiBase = this.urlFromFetchOptions(options);

    const { uid, encryptionKey, version } = item.serialize();

    const json = await this.newCall<IteratorListResponse<CollectionItemRevisionJsonRead>>([item.uid, "revision"], undefined, apiBase);
    return {
      ...json,
      data: json.data.map((val) => EncryptedCollectionItem.deserialize({
        uid,
        encryptionKey,
        version,
        etag: val.uid, // We give revisions their old etag
        content: val,
      })),
    };
  }

  public create(item: EncryptedCollectionItem): Promise<{}> {
    const extra = {
      method: "post",
      body: msgpackEncode(item.serialize()),
    };

    return this.newCall(undefined, extra);
  }

  public async fetchUpdates(items: EncryptedCollectionItem[], options?: ItemFetchOptions): Promise<CollectionItemListResponse<EncryptedCollectionItem>> {
    const apiBase = this.urlFromFetchOptions(options);
    // We only use stoken if available
    const wantEtag = !options?.stoken;

    const extra = {
      method: "post",
      body: msgpackEncode(items?.map((x) => ({ uid: x.uid, etag: ((wantEtag) ? x.etag : undefined) }))),
    };

    const json = await this.newCall<CollectionItemListResponse<CollectionItemJsonRead>>(["fetch_updates"], extra, apiBase);
    const data = json.data;
    return {
      ...json,
      data: data.map((val) => EncryptedCollectionItem.deserialize(val)),
    };
  }

  public batch(items: EncryptedCollectionItem[], deps?: EncryptedCollectionItem[], options?: ItemFetchOptions): Promise<{}> {
    const apiBase = this.urlFromFetchOptions(options);

    const extra = {
      method: "post",
      body: msgpackEncode({
        items: items.map((x) => x.serialize()),
        deps: deps?.map((x) => ({ uid: x.uid, etag: x.etag })),
      }),
    };

    return this.newCall(["batch"], extra, apiBase);
  }

  public transaction(items: EncryptedCollectionItem[], deps?: EncryptedCollectionItem[], options?: ItemFetchOptions): Promise<{}> {
    const apiBase = this.urlFromFetchOptions(options);

    const extra = {
      method: "post",
      body: msgpackEncode({
        items: items.map((x) => x.serialize()),
        deps: deps?.map((x) => ({ uid: x.uid, etag: x.etag })),
      }),
    };

    return this.newCall(["transaction"], extra, apiBase);
  }
}

export class CollectionInvitationManagerOnline extends BaseManager {
  constructor(etebase: AccountOnlineData) {
    super(etebase, ["invitation"]);
  }

  public async listIncoming(options?: InvitationFetchOptions): Promise<CollectionInvitationListResponse<SignedInvitationRead>> {
    const apiBase = this.urlFromFetchOptions(options);

    const json = await this.newCall<CollectionInvitationListResponse<SignedInvitationRead>>(["incoming"], undefined, apiBase);
    return {
      ...json,
      data: json.data.map((val) => val),
    };
  }

  public async listOutgoing(options?: InvitationFetchOptions): Promise<CollectionInvitationListResponse<SignedInvitationRead>> {
    const apiBase = this.urlFromFetchOptions(options);

    const json = await this.newCall<CollectionInvitationListResponse<SignedInvitationRead>>(["outgoing"], undefined, apiBase);
    return {
      ...json,
      data: json.data.map((val) => val),
    };
  }

  public async accept(invitation: SignedInvitationRead, encryptionKey: Uint8Array): Promise<{}> {
    const extra = {
      method: "post",
      body: msgpackEncode({
        encryptionKey,
      }),
    };

    return this.newCall(["incoming", invitation.uid, "accept"], extra);
  }

  public async reject(invitation: SignedInvitationRead): Promise<{}> {
    const extra = {
      method: "delete",
    };

    return this.newCall(["incoming", invitation.uid], extra);
  }

  public async fetchUserProfile(username: string): Promise<UserProfile> {
    const apiBase = this.apiBase.clone().search({
      username: username,
    });

    return this.newCall(["outgoing", "fetch_user_profile"], undefined, apiBase);
  }

  public async invite(invitation: SignedInvitationWrite): Promise<{}> {
    const extra = {
      method: "post",
      body: msgpackEncode(invitation),
    };

    return this.newCall(["outgoing"], extra);
  }

  public async disinvite(invitation: SignedInvitationRead): Promise<{}> {
    const extra = {
      method: "delete",
    };

    return this.newCall(["outgoing", invitation.uid], extra);
  }
}

export class CollectionMemberManagerOnline extends BaseManager {
  constructor(etebase: AccountOnlineData, col: EncryptedCollection) {
    super(etebase, ["collection", col.uid, "member"]);
  }

  public async list(options?: MemberFetchOptions): Promise<CollectionMemberListResponse<CollectionMember>> {
    const apiBase = this.urlFromFetchOptions(options);

    return this.newCall<CollectionMemberListResponse<CollectionMember>>(undefined, undefined, apiBase);
  }

  public async remove(username: string): Promise<{}> {
    const extra = {
      method: "delete",
    };

    return this.newCall([username], extra);
  }

  public async leave(): Promise<{}> {
    const extra = {
      method: "post",
    };

    return this.newCall(["leave"], extra);
  }

  public async modifyAccessLevel(username: string, accessLevel: CollectionAccessLevel): Promise<{}> {
    const extra = {
      method: "patch",
      body: msgpackEncode({
        accessLevel,
      }),
    };

    return this.newCall([username], extra);
  }
}
