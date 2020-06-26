import * as Constants from "./Constants";

import { CryptoManager, AsymmetricCryptoManager, concatArrayBuffersArrays } from "./Crypto";
import { IntegrityError } from "./Exceptions";
import { base64, fromBase64, toBase64, fromString, toString, randomBytes, memcmp, symmetricKeyLength, symmetricTagLength } from "./Helpers";

export type CollectionType = string;

export type ContentType = File | Blob | Uint8Array | string | null;

export interface CollectionMetadata extends CollectionItemMetadata {
  name: string;
  description?: string;
  color?: string;
  extra?: {[key: string]: any}; // This is how per-type data should be set. The key is a unique name for the extra data
}

export interface CollectionItemMetadata {
  type: string;
  name?: string; // The name of the item, e.g. filename in case of files
  mtime?: number; // The modification time
  extra?: {[key: string]: any}; // This is how per-type data should be set. The key is a unique name for the extra data
}

export type ChunkJson = [base64, base64?];

export interface CollectionItemRevisionJsonWrite {
  uid: base64;
  salt: base64;
  meta: base64;

  chunks: ChunkJson[];
  deleted: boolean;
}

export interface CollectionItemRevisionJsonRead extends CollectionItemRevisionJsonWrite {
  chunks: ChunkJson[];
}

export interface CollectionItemJsonWrite {
  uid: base64;
  version: number;

  encryptionKey?: base64;
  content: CollectionItemRevisionJsonWrite;

  etag: string | null;
}

export interface CollectionItemJsonRead extends CollectionItemJsonWrite {
  content: CollectionItemRevisionJsonRead;
}

export enum CollectionAccessLevel {
  Admin = "adm",
  ReadWrite = "rw",
  ReadOnly = "ro",
}

export interface CollectionJsonWrite extends CollectionItemJsonWrite {
  collectionKey: base64;
}

export interface CollectionJsonRead extends CollectionJsonWrite {
  accessLevel: CollectionAccessLevel;
  stoken: string | null; // FIXME: hack, we shouldn't expose it here...

  content: CollectionItemRevisionJsonRead;
}

export interface SignedInvitationWrite {
  uid: base64;
  version: number;
  username: string;

  collection: base64;
  accessLevel: CollectionAccessLevel;

  signedEncryptionKey: base64;
}

export interface SignedInvitationRead extends SignedInvitationWrite {
  fromPubkey: base64;
}

function genUidBase64(): base64 {
  return toBase64(randomBytes(32)).substr(0, 24);
}

export class MainCryptoManager extends CryptoManager {
  protected Main = true; // So classes are different

  constructor(key: Uint8Array, version: number = Constants.CURRENT_VERSION) {
    super(key, "Main", version);
  }

  public getLoginCryptoManager(): AsymmetricCryptoManager {
    return AsymmetricCryptoManager.keygen(this.asymKeySeed);
  }

  public getAccountCryptoManager(privkey: Uint8Array): AccountCryptoManager {
    return new AccountCryptoManager(privkey, this.version);
  }

  public getIdentityCryptoManager(privkey: Uint8Array): AsymmetricCryptoManager {
    return AsymmetricCryptoManager.fromPrivkey(privkey);
  }
}

export class AccountCryptoManager extends CryptoManager {
  protected Account = true; // So classes are different

  constructor(key: Uint8Array, version: number = Constants.CURRENT_VERSION) {
    super(key, "Acct", version);
  }
}

export class CollectionCryptoManager extends CryptoManager {
  protected Collection = true; // So classes are different

  constructor(key: Uint8Array, version: number = Constants.CURRENT_VERSION) {
    super(key, "Col", version);
  }
}

export class CollectionItemCryptoManager extends CryptoManager {
  protected CollectionItem = true; // So classes are different

  constructor(key: Uint8Array, version: number = Constants.CURRENT_VERSION) {
    super(key, "ColItem", version);
  }
}

export class StorageCryptoManager extends CryptoManager {
  protected Storage = true; // So classes are different

  constructor(key: Uint8Array, version: number = Constants.CURRENT_VERSION) {
    super(key, "Stor", version);
  }
}

export function getMainCryptoManager(mainEncryptionKey: Uint8Array, version: number) {
  return new MainCryptoManager(mainEncryptionKey, version);
}

class EncryptedRevision<CM extends CollectionItemCryptoManager> {
  public uid: base64;
  public salt: Uint8Array;
  public meta: Uint8Array;
  public deleted: boolean;

  public chunks: [base64, Uint8Array?][];

  constructor() {
    this.deleted = false;
  }

  public static async create<CM extends CollectionItemCryptoManager>(cryptoManager: CM, additionalData: Uint8Array, meta: any, content: Uint8Array): Promise<EncryptedRevision<CM>> {
    const ret = new EncryptedRevision<CM>();
    ret.chunks = [];
    await ret.setMeta(cryptoManager, additionalData, meta);
    await ret.setContent(cryptoManager, additionalData, content);

    return ret;
  }

  public static deserialize<CM extends CollectionItemCryptoManager>(json: CollectionItemRevisionJsonRead) {
    const { uid, salt, meta, chunks, deleted } = json;
    const ret = new EncryptedRevision<CM>();
    ret.uid = uid;
    ret.salt = fromBase64(salt);
    ret.meta = fromBase64(meta);
    ret.deleted = deleted;
    ret.chunks = chunks.map((chunk) => {
      return [chunk[0], (chunk[1]) ? fromBase64(chunk[1]) : undefined];
    });

    return ret;
  }

  public serialize() {
    const ret: CollectionItemRevisionJsonWrite = {
      uid: this.uid,
      salt: toBase64(this.salt),
      meta: toBase64(this.meta),
      deleted: this.deleted,

      chunks: this.chunks.map((chunk) => [chunk[0], (chunk[1]) ? toBase64(chunk[1]) : undefined]),
    };

    return ret;
  }

  public async verify(cryptoManager: CM, additionalData: Uint8Array) {
    const calculatedMac = await this.calculateMac(cryptoManager, additionalData);
    if (memcmp(
      fromBase64(this.uid),
      calculatedMac
    )) {
      return true;
    } else {
      throw new IntegrityError(`mac verification failed. Expected: ${this.uid} got: ${toBase64(calculatedMac)}`);
    }
  }

  private async calculateMac(cryptoManager: CM, additionalData: Uint8Array) {
    const cryptoMac = cryptoManager.getCryptoMac();
    cryptoMac.updateWithLenPrefix(Uint8Array.from([(this.deleted) ? 1 : 0]));
    cryptoMac.updateWithLenPrefix(this.salt);
    cryptoMac.updateWithLenPrefix(additionalData);
    cryptoMac.updateWithLenPrefix(this.meta.subarray(-1 * symmetricTagLength));
    this.chunks.forEach((chunk) =>
      cryptoMac.updateWithLenPrefix(fromBase64(chunk[0]))
    );

    return cryptoMac.finalize();
  }

  private async updateMac(cryptoManager: CM, additionalData: Uint8Array) {
    this.salt = randomBytes(24);
    const mac = await this.calculateMac(cryptoManager, additionalData);
    this.uid = toBase64(mac);
  }

  public async setMeta(cryptoManager: CM, additionalData: Uint8Array, meta: any): Promise<void> {
    this.meta = cryptoManager.encrypt(fromString(JSON.stringify(meta)), null);

    await this.updateMac(cryptoManager, additionalData);
  }

  public async decryptMeta(cryptoManager: CM): Promise<any> {
    return JSON.parse(toString(cryptoManager.decrypt(this.meta, null)));
  }

  public async setContent(cryptoManager: CM, additionalData: Uint8Array, content: Uint8Array): Promise<void> {
    if (content.length > 0) {
      // FIXME: need to actually chunkify
      const encContent = cryptoManager.encryptDetached(content);
      this.chunks = [[toBase64(encContent[0]), encContent[1]]];
    } else {
      this.chunks = [];
    }

    await this.updateMac(cryptoManager, additionalData);
  }

  public async delete(cryptoManager: CM, additionalData: Uint8Array): Promise<void> {
    this.deleted = true;
    await this.updateMac(cryptoManager, additionalData);
  }

  public async decryptContent(cryptoManager: CM): Promise<Uint8Array> {
    return concatArrayBuffersArrays(
      this.chunks.map((chunk) => cryptoManager.decryptDetached(chunk[1]!, fromBase64(chunk[0]))))
    ;
  }

  public clone() {
    const rev = new EncryptedRevision<CM>();
    rev.uid = this.uid;
    rev.salt = this.salt;
    rev.meta = this.meta;
    rev.chunks = this.chunks;
    rev.deleted = this.deleted;
    return rev;
  }
}

export class EncryptedCollection {
  private collectionKey: Uint8Array;
  public item: EncryptedCollectionItem;

  public accessLevel: CollectionAccessLevel;
  public stoken: string | null; // FIXME: hack, we shouldn't expose it here...

  public static async create(parentCryptoManager: AccountCryptoManager, meta: CollectionMetadata, content: Uint8Array): Promise<EncryptedCollection> {
    const ret = new EncryptedCollection();
    ret.collectionKey = parentCryptoManager.encrypt(randomBytes(symmetricKeyLength));

    ret.accessLevel = CollectionAccessLevel.Admin;
    ret.stoken = null;

    const cryptoManager = ret.getCryptoManager(parentCryptoManager, Constants.CURRENT_VERSION);

    ret.item = await EncryptedCollectionItem.create(cryptoManager, meta, content);

    return ret;
  }

  public static deserialize(json: CollectionJsonRead): EncryptedCollection {
    const { stoken, accessLevel, collectionKey } = json;
    const ret = new EncryptedCollection();
    ret.collectionKey = fromBase64(collectionKey);

    ret.item = EncryptedCollectionItem.deserialize(json);

    ret.accessLevel = accessLevel;
    ret.stoken = stoken;

    return ret;
  }

  public serialize() {
    const ret: CollectionJsonWrite = {
      ...this.item.serialize(),

      collectionKey: toBase64(this.collectionKey),
    };

    return ret;
  }

  public __markSaved() {
    this.item.__markSaved();
  }

  public async verify(cryptoManager: CollectionCryptoManager) {
    const itemCryptoManager = this.item.getCryptoManager(cryptoManager);
    return this.item.verify(itemCryptoManager);
  }

  public async setMeta(cryptoManager: CollectionCryptoManager, meta: CollectionMetadata): Promise<void> {
    const itemCryptoManager = this.item.getCryptoManager(cryptoManager);
    return this.item.setMeta(itemCryptoManager, meta);
  }

  public async decryptMeta(cryptoManager: CollectionCryptoManager): Promise<CollectionMetadata> {
    this.verify(cryptoManager);
    const itemCryptoManager = this.item.getCryptoManager(cryptoManager);
    return this.item.decryptMeta(itemCryptoManager) as Promise<CollectionMetadata>;
  }

  public async setContent(cryptoManager: CollectionCryptoManager, content: Uint8Array): Promise<void> {
    const itemCryptoManager = this.item.getCryptoManager(cryptoManager);
    return this.item.setContent(itemCryptoManager, content);
  }

  public async decryptContent(cryptoManager: CollectionCryptoManager): Promise<Uint8Array> {
    this.verify(cryptoManager);
    const itemCryptoManager = this.item.getCryptoManager(cryptoManager);
    return this.item.decryptContent(itemCryptoManager);
  }

  public async delete(cryptoManager: CollectionCryptoManager): Promise<void> {
    const itemCryptoManager = this.item.getCryptoManager(cryptoManager);
    return this.item.delete(itemCryptoManager);
  }

  public get isDeleted() {
    return this.item.isDeleted;
  }

  public get uid() {
    return this.item.uid;
  }

  public get etag() {
    return this.item.etag;
  }

  public get version() {
    return this.item.version;
  }


  public async createInvitation(parentCryptoManager: AccountCryptoManager, identCryptoManager: AsymmetricCryptoManager, username: string, pubkey: Uint8Array, accessLevel: CollectionAccessLevel): Promise<SignedInvitationWrite> {
    const uid = randomBytes(32);
    const encryptionKey = parentCryptoManager.decrypt(this.collectionKey);
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

  public getCryptoManager(parentCryptoManager: AccountCryptoManager, version?: number) {
    const encryptionKey = parentCryptoManager.decrypt(this.collectionKey);

    return new CollectionCryptoManager(encryptionKey, version ?? this.version);
  }
}

export class EncryptedCollectionItem {
  public uid: base64;
  public version: number;
  private encryptionKey: Uint8Array | null;
  private content: EncryptedRevision<CollectionItemCryptoManager>;

  public etag: string | null;

  public static async create(parentCryptoManager: CollectionCryptoManager, meta: CollectionItemMetadata, content: Uint8Array): Promise<EncryptedCollectionItem> {
    const ret = new EncryptedCollectionItem();
    ret.uid = genUidBase64();
    ret.version = Constants.CURRENT_VERSION;
    ret.encryptionKey = null;

    ret.etag = null;

    const cryptoManager = ret.getCryptoManager(parentCryptoManager);

    ret.content = await EncryptedRevision.create(cryptoManager, ret.getAdditionalMacData(), meta, content);

    return ret;
  }

  public static deserialize(json: CollectionItemJsonRead): EncryptedCollectionItem {
    const { uid, version, encryptionKey, content } = json;
    const ret = new EncryptedCollectionItem();
    ret.uid = uid;
    ret.version = version;
    ret.encryptionKey = encryptionKey ? fromBase64(encryptionKey) : null;

    ret.content = EncryptedRevision.deserialize(content);

    ret.etag = ret.content.uid;

    return ret;
  }

  public serialize() {
    const ret: CollectionItemJsonWrite = {
      uid: this.uid,
      version: this.version,
      encryptionKey: this.encryptionKey ? toBase64(this.encryptionKey) : undefined,
      etag: this.etag,

      content: this.content.serialize(),
    };

    return ret;
  }

  public __markSaved() {
    this.etag = this.content.uid;
  }

  private isLocallyChanged() {
    return this.etag !== this.content.uid;
  }

  public async verify(cryptoManager: CollectionItemCryptoManager) {
    return this.content.verify(cryptoManager, this.getAdditionalMacData());
  }

  public async setMeta(cryptoManager: CollectionItemCryptoManager, meta: CollectionItemMetadata): Promise<void> {
    let rev = this.content;
    if (!this.isLocallyChanged()) {
      rev = this.content.clone();
    }
    await rev.setMeta(cryptoManager, this.getAdditionalMacData(), meta);

    this.content = rev;
  }

  public async decryptMeta(cryptoManager: CollectionItemCryptoManager): Promise<CollectionItemMetadata> {
    this.verify(cryptoManager);
    return this.content.decryptMeta(cryptoManager);
  }

  public async setContent(cryptoManager: CollectionItemCryptoManager, content: Uint8Array): Promise<void> {
    let rev = this.content;
    if (!this.isLocallyChanged()) {
      rev = this.content.clone();
    }
    await rev.setContent(cryptoManager, this.getAdditionalMacData(), content);

    this.content = rev;
  }

  public async decryptContent(cryptoManager: CollectionItemCryptoManager): Promise<Uint8Array> {
    this.verify(cryptoManager);
    return this.content.decryptContent(cryptoManager);
  }

  public async delete(cryptoManager: CollectionItemCryptoManager): Promise<void> {
    let rev = this.content;
    if (!this.isLocallyChanged()) {
      rev = this.content.clone();
    }
    await rev.delete(cryptoManager, this.getAdditionalMacData());

    this.content = rev;
  }

  public get isDeleted() {
    return this.content.deleted;
  }

  public getCryptoManager(parentCryptoManager: CollectionCryptoManager) {
    const encryptionKey = (this.encryptionKey) ?
      parentCryptoManager.decrypt(this.encryptionKey) :
      parentCryptoManager.deriveSubkey(fromString(this.uid));

    return new CollectionItemCryptoManager(encryptionKey, this.version);
  }

  protected getAdditionalMacData() {
    return fromString(this.uid);
  }
}

