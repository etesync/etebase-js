import * as Constants from './Constants';

import { CryptoManager, sodium, AsymmetricCryptoManager, concatArrayBuffersArrays } from './Crypto';
import { IntegrityError } from './Exceptions';
import { base62, base64, toBase64 } from './Helpers';

export type CollectionType = string;

export type ContentType = File | Blob | Uint8Array | string | null;

export interface CollectionMetadata {
  type: CollectionType;
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

  etag: string | null;
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

  etag: string | null;
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

  collection: base62;
  accessLevel: CollectionAccessLevel;

  signedEncryptionKey: base64;
}

export interface SignedInvitationRead extends SignedInvitationWrite {
  fromPubkey: base64;
}

function genUidBase62(): base62 {
  const uid = sodium.to_base64(sodium.randombytes_buf(32)).substr(0, 24);
  // FIXME: not the best function, but we don't care about the bias for now
  return uid.replace(/-/g, 'a').replace(/_/g, 'b');
}

export class MainCryptoManager extends CryptoManager {
  protected Main = true; // So classes are different

  constructor(key: Uint8Array, version: number = Constants.CURRENT_VERSION) {
    super(key, 'Main', version);
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
    super(key, 'Acct', version);
  }
}

export class CollectionCryptoManager extends CryptoManager {
  protected Collection = true; // So classes are different

  constructor(key: Uint8Array, version: number = Constants.CURRENT_VERSION) {
    super(key, 'Col', version);
  }
}

export class CollectionItemCryptoManager extends CryptoManager {
  protected CollectionItem = true; // So classes are different

  constructor(key: Uint8Array, version: number = Constants.CURRENT_VERSION) {
    super(key, 'ColItem', version);
  }
}

export function getMainCryptoManager(mainEncryptionKey: Uint8Array, version: number) {
  return new MainCryptoManager(mainEncryptionKey, version);
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
    ret.chunks = [];
    await ret.setMeta(cryptoManager, additionalData, meta);
    await ret.setContent(cryptoManager, additionalData, content);

    return ret;
  }

  public static deserialize<CM extends CollectionCryptoManager | CollectionItemCryptoManager>(json: CollectionItemRevisionJsonRead) {
    const { uid, meta, chunks, deleted } = json;
    const ret = new EncryptedRevision<CM>();
    ret.uid = uid;
    ret.meta = sodium.from_base64(meta);
    ret.deleted = deleted; // FIXME: this should also be part of the meta additional data too. Probably can remove from the major verification everything that's verified by meta.
    ret.chunks = chunks.map((chunk) => {
      return [chunk[0], (chunk[1]) ? sodium.from_base64(chunk[1]) : undefined];
    });

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

  public async setMeta(cryptoManager: CM, additionalData: Uint8Array[], meta: any): Promise<void> {
    const additionalDataMerged = concatArrayBuffersArrays(additionalData);
    this.meta = cryptoManager.encrypt(sodium.from_string(JSON.stringify(meta)), additionalDataMerged);

    const mac = await this.calculateMac(cryptoManager, additionalData);
    this.uid = sodium.to_base64(mac);
  }

  public async decryptMeta(cryptoManager: CM, additionalData: Uint8Array[]): Promise<any> {
    const additionalDataMerged = concatArrayBuffersArrays(additionalData);
    return JSON.parse(sodium.to_string(cryptoManager.decrypt(this.meta, additionalDataMerged)));
  }

  public async setContent(cryptoManager: CM, additionalData: Uint8Array[], content: Uint8Array): Promise<void> {
    const meta = await this.decryptMeta(cryptoManager, additionalData);
    await this.setMeta(cryptoManager, additionalData, meta);

    // FIXME: need to actually chunkify
    const encContent = cryptoManager.encryptDetached(content);
    this.chunks = [[sodium.to_base64(encContent[0]), encContent[1]]];

    const mac = await this.calculateMac(cryptoManager, additionalData);
    this.uid = sodium.to_base64(mac);
  }

  public async decryptContent(cryptoManager: CM): Promise<Uint8Array> {
    return concatArrayBuffersArrays(
      this.chunks.map((chunk) => cryptoManager.decryptDetached(chunk[1]!, sodium.from_base64(chunk[0]))))
    ;
  }

  public clone() {
    const rev = new EncryptedRevision<CM>();
    rev.uid = this.uid;
    rev.meta = this.meta;
    rev.chunks = this.chunks;
    rev.deleted = this.deleted;
    return rev;
  }
}

export class EncryptedCollection {
  public uid: base62;
  public version: number;
  private encryptionKey: Uint8Array;
  private content: EncryptedRevision<CollectionCryptoManager>;

  public accessLevel: CollectionAccessLevel;
  public etag: string | null;
  public stoken: string | null; // FIXME: hack, we shouldn't expose it here...

  public static async create(parentCryptoManager: AccountCryptoManager, meta: CollectionMetadata, content: Uint8Array): Promise<EncryptedCollection> {
    const ret = new EncryptedCollection();
    ret.uid = genUidBase62();
    ret.version = Constants.CURRENT_VERSION;
    ret.encryptionKey = parentCryptoManager.encrypt(sodium.crypto_aead_chacha20poly1305_ietf_keygen());

    ret.accessLevel = CollectionAccessLevel.Admin;
    ret.etag = null;
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

    ret.etag = ret.content.uid;

    return ret;
  }

  public serialize() {
    const ret: CollectionJsonWrite = {
      uid: this.uid,
      version: this.version,
      encryptionKey: sodium.to_base64(this.encryptionKey),
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

  public async verify(cryptoManager: CollectionCryptoManager) {
    return this.content.verify(cryptoManager, this.getAdditionalMacData());
  }

  public async setMeta(cryptoManager: CollectionCryptoManager, meta: CollectionMetadata): Promise<void> {
    let rev = this.content;
    if (!this.isLocallyChanged()) {
      rev = this.content.clone();
    }
    await rev.setMeta(cryptoManager, this.getAdditionalMacData(), meta);

    this.content = rev;
  }

  public async decryptMeta(cryptoManager: CollectionCryptoManager): Promise<CollectionMetadata> {
    this.verify(cryptoManager);
    return this.content.decryptMeta(cryptoManager, this.getAdditionalMacData());
  }

  public async setContent(cryptoManager: CollectionCryptoManager, content: Uint8Array): Promise<void> {
    let rev = this.content;
    if (!this.isLocallyChanged()) {
      rev = this.content.clone();
    }
    await rev.setContent(cryptoManager, this.getAdditionalMacData(), content);

    this.content = rev;
  }

  public async decryptContent(cryptoManager: CollectionCryptoManager): Promise<Uint8Array> {
    this.verify(cryptoManager);
    return this.content.decryptContent(cryptoManager);
  }

  public async createInvitation(parentCryptoManager: AccountCryptoManager, identCryptoManager: AsymmetricCryptoManager, username: string, pubkey: Uint8Array, accessLevel: CollectionAccessLevel): Promise<SignedInvitationWrite> {
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

  public getCryptoManager(parentCryptoManager: AccountCryptoManager) {
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

  public etag: string | null;

  public static async create(parentCryptoManager: CollectionCryptoManager, meta: CollectionItemMetadata, content: Uint8Array): Promise<EncryptedCollectionItem> {
    const ret = new EncryptedCollectionItem();
    ret.uid = genUidBase62();
    ret.version = Constants.CURRENT_VERSION;
    ret.encryptionKey = parentCryptoManager.encrypt(sodium.crypto_aead_chacha20poly1305_ietf_keygen());

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
    ret.encryptionKey = sodium.from_base64(encryptionKey);

    ret.content = EncryptedRevision.deserialize(content);

    ret.etag = ret.content.uid;

    return ret;
  }

  public serialize() {
    const ret: CollectionItemJsonWrite = {
      uid: this.uid,
      version: this.version,
      encryptionKey: sodium.to_base64(this.encryptionKey),
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
    return this.content.decryptMeta(cryptoManager, this.getAdditionalMacData());
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

  public getCryptoManager(parentCryptoManager: CollectionCryptoManager) {
    const encryptionKey = parentCryptoManager.decrypt(this.encryptionKey);

    return new CollectionItemCryptoManager(encryptionKey, this.version);
  }

  protected getAdditionalMacData() {
    return [sodium.from_string(this.uid)];
  }
}

