import * as Constants from "./Constants";

import { CryptoManager, BoxCryptoManager, LoginCryptoManager, concatArrayBuffersArrays } from "./Crypto";
import { IntegrityError, MissingContentError } from "./Exceptions";
import { base64, fromBase64, toBase64, fromString, randomBytes, symmetricKeyLength, msgpackEncode, msgpackDecode, bufferPad, bufferUnpad, memcmp, shuffle, bufferPadMeta } from "./Helpers";

export type CollectionType = string;

export type ContentType = File | Blob | Uint8Array | string | null;

export interface CollectionMetadata extends ItemMetadata {
  type: string;
  name: string;
  description?: string;
  color?: string;
}

export interface ItemMetadata {
  type?: string;
  name?: string; // The name of the item, e.g. filename in case of files
  mtime?: number; // The modification time
  extra?: {[key: string]: any}; // This is how per-type data should be set. The key is a unique name for the extra data
}

export type ChunkJson = [base64, Uint8Array?];

export interface CollectionItemRevisionJsonWrite {
  uid: base64;
  meta: Uint8Array;

  chunks: ChunkJson[];
  deleted: boolean;
}

export type CollectionItemRevisionJsonRead = CollectionItemRevisionJsonWrite;

export interface CollectionItemJsonWrite {
  uid: base64;
  version: number;

  encryptionKey?: Uint8Array;
  content: CollectionItemRevisionJsonWrite;

  etag: string | null;
}

export type CollectionItemJsonRead = CollectionItemJsonWrite;

export enum CollectionAccessLevel {
  ReadOnly = 0,
  Admin = 1,
  ReadWrite = 2,
}

export interface CollectionJsonWrite {
  collectionKey: Uint8Array;
  item: CollectionItemJsonWrite;
}

export interface CollectionJsonRead extends CollectionJsonWrite {
  accessLevel: CollectionAccessLevel;
  stoken: string | null; // FIXME: hack, we shouldn't expose it here...

  item: CollectionItemJsonRead;
}

export interface SignedInvitationWrite {
  uid: base64;
  version: number;
  username: string;

  collection: base64;
  accessLevel: CollectionAccessLevel;

  signedEncryptionKey: Uint8Array;
}

export interface SignedInvitationRead extends SignedInvitationWrite {
  fromPubkey: Uint8Array;
}

function genUidBase64(): base64 {
  return toBase64(randomBytes(24));
}

export class MainCryptoManager extends CryptoManager {
  protected Main = true; // So classes are different

  constructor(key: Uint8Array, version: number = Constants.CURRENT_VERSION) {
    super(key, "Main", version);
  }

  public getLoginCryptoManager(): LoginCryptoManager {
    return LoginCryptoManager.keygen(this.asymKeySeed);
  }

  public getAccountCryptoManager(privkey: Uint8Array): AccountCryptoManager {
    return new AccountCryptoManager(privkey, this.version);
  }

  public getIdentityCryptoManager(privkey: Uint8Array): BoxCryptoManager {
    return BoxCryptoManager.fromPrivkey(privkey);
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
    const { uid, meta, chunks, deleted } = json;
    const ret = new EncryptedRevision<CM>();
    ret.uid = uid;
    ret.meta = meta;
    ret.deleted = deleted;
    ret.chunks = chunks.map((chunk) => {
      return [chunk[0], chunk[1] ?? undefined];
    });

    return ret;
  }

  public serialize() {
    const ret: CollectionItemRevisionJsonWrite = {
      uid: this.uid,
      meta: this.meta,
      deleted: this.deleted,

      chunks: this.chunks.map((chunk) => [chunk[0], chunk[1] ?? undefined]),
    };

    return ret;
  }

  public static cacheLoad<CM extends CollectionItemCryptoManager>(cached_: Uint8Array) {
    const cached = msgpackDecode(cached_) as any[];

    const ret = new EncryptedRevision<CM>();
    ret.uid = toBase64(cached[0]);
    ret.meta = cached[1];
    ret.deleted = cached[2];
    ret.chunks = cached[3].map((chunk: Uint8Array[]) => [
      toBase64(chunk[0]),
      chunk[1] ?? undefined,
    ]);

    return ret;
  }

  public cacheSave(saveContent: boolean): Uint8Array {
    return msgpackEncode([
      fromBase64(this.uid),
      this.meta,
      this.deleted,
      ((saveContent) ?
        this.chunks.map((chunk) => [fromBase64(chunk[0]), chunk[1] ?? null]) :
        this.chunks.map((chunk) => [fromBase64(chunk[0])])
      ),
    ]);
  }

  public async verify(cryptoManager: CM, additionalData: Uint8Array) {
    const adHash = await this.calculateAdHash(cryptoManager, additionalData);
    const mac = fromBase64(this.uid);

    try {
      cryptoManager.verify(this.meta, mac, adHash);
      return true;
    } catch (e) {
      throw new IntegrityError(`mac verification failed.`);
    }
  }

  private async calculateAdHash(cryptoManager: CM, additionalData: Uint8Array) {
    const cryptoMac = cryptoManager.getCryptoMac();
    cryptoMac.update(Uint8Array.from([(this.deleted) ? 1 : 0]));
    cryptoMac.updateWithLenPrefix(additionalData);

    // We hash the chunks separately so that the server can (in the future) return just the hash instead of the full
    // chunk list if requested - useful for asking for collection updates
    const chunksHash = cryptoManager.getCryptoMac(false);
    this.chunks.forEach((chunk) =>
      chunksHash.update(fromBase64(chunk[0]))
    );

    cryptoMac.update(chunksHash.finalize());

    return cryptoMac.finalize();
  }

  public async setMeta(cryptoManager: CM, additionalData: Uint8Array, meta: any): Promise<void> {
    const adHash = await this.calculateAdHash(cryptoManager, additionalData);

    const encContent = cryptoManager.encryptDetached(bufferPadMeta(msgpackEncode(meta)), adHash);

    this.meta = encContent[1];
    this.uid = toBase64(encContent[0]);
  }

  public async getMeta(cryptoManager: CM, additionalData: Uint8Array): Promise<any> {
    const mac = fromBase64(this.uid);
    const adHash = await this.calculateAdHash(cryptoManager, additionalData);

    return msgpackDecode(bufferUnpad(cryptoManager.decryptDetached(this.meta, mac, adHash)));
  }

  public async setContent(cryptoManager: CM, additionalData: Uint8Array, content: Uint8Array): Promise<void> {
    const meta = await this.getMeta(cryptoManager, additionalData);

    let chunks: [base64, Uint8Array][] = [];

    const minChunk = 1 << 14;
    const maxChunk = 1 << 16;
    let chunkStart = 0;

    // Only try chunking if our content is larger than the minimum chunk size
    if (content.length > minChunk) {
      // FIXME: figure out what to do with mask - should it be configurable?
      const buzhash = cryptoManager.getChunker();
      const mask = (1 << 12) - 1;

      let pos = 0;
      while (pos < content.length) {
        buzhash.update(content[pos]);
        if (pos - chunkStart >= minChunk) {
          if ((pos - chunkStart >= maxChunk) || (buzhash.split(mask))) {
            const buf = content.subarray(chunkStart, pos);
            const hash = toBase64(cryptoManager.calculateMac(buf));
            chunks.push([hash, buf]);
            chunkStart = pos;
          }
        }
        pos++;
      }
    }

    if (chunkStart < content.length) {
      const buf = content.subarray(chunkStart);
      const hash = toBase64(cryptoManager.calculateMac(buf));
      chunks.push([hash, buf]);
    }

    // Shuffle the items and save the ordering if we have more than one
    if (chunks.length > 0) {
      const indices = shuffle(chunks);

      // Filter duplicates and construct the indice list.
      const uidIndices = new Map<string, number>();
      chunks = chunks.filter((chunk, i) => {
        const uid = chunk[0];
        const previousIndex = uidIndices.get(uid);
        if (previousIndex !== undefined) {
          indices[i] = previousIndex;
          return false;
        } else {
          uidIndices.set(uid, i);
          return true;
        }
      });

      // If we have more than one chunk we need to encode the mapping header in the last chunk
      if (indices.length > 1) {
        // We encode it in an array so we can extend it later on if needed
        const buf = msgpackEncode([indices]);
        const hash = toBase64(cryptoManager.calculateMac(buf));
        chunks.push([hash, buf]);
      }
    }

    // Encrypt all of the chunks
    this.chunks = chunks.map((chunk) => [chunk[0], cryptoManager.encrypt(bufferPad(chunk[1]))]);

    await this.setMeta(cryptoManager, additionalData, meta);
  }

  public async getContent(cryptoManager: CM): Promise<Uint8Array> {
    let indices: number[] = [0];
    const decryptedChunks: Uint8Array[] = this.chunks.map((chunk) => {
      if (!chunk[1]) {
        throw new MissingContentError("Missing content for item. Please download it using `downloadMissingContent`");
      }

      const buf = bufferUnpad(cryptoManager.decrypt(chunk[1]));
      const hash = cryptoManager.calculateMac(buf);
      if (!memcmp(hash, fromBase64(chunk[0]))) {
        throw new IntegrityError(`The content's mac is different to the expected mac (${chunk[0]})`);
      }
      return buf;
    });

    // If we have more than one chunk we have the mapping header in the last chunk
    if (this.chunks.length > 1) {
      const lastChunk = msgpackDecode(decryptedChunks.pop()!) as [number[]];
      indices = lastChunk[0];
    }

    // We need to unshuffle the chunks
    if (indices.length > 1) {
      const sortedChunks: Uint8Array[] = [];
      for (const index of indices) {
        sortedChunks.push(decryptedChunks[index]);
      }

      return concatArrayBuffersArrays(sortedChunks);
    } else if (decryptedChunks.length > 0) {
      return decryptedChunks[0];
    } else {
      return new Uint8Array();
    }
  }

  public async delete(cryptoManager: CM, additionalData: Uint8Array): Promise<void> {
    const meta = await this.getMeta(cryptoManager, additionalData);

    this.deleted = true;

    await this.setMeta(cryptoManager, additionalData, meta);
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
    ret.collectionKey = collectionKey;

    ret.item = EncryptedCollectionItem.deserialize(json.item);

    ret.accessLevel = accessLevel;
    ret.stoken = stoken;

    return ret;
  }

  public serialize() {
    const ret: CollectionJsonWrite = {
      item: this.item.serialize(),

      collectionKey: this.collectionKey,
    };

    return ret;
  }

  public static cacheLoad(cached_: Uint8Array) {
    const cached = msgpackDecode(cached_) as any[];

    const ret = new EncryptedCollection();
    ret.collectionKey = cached[1];
    ret.accessLevel = cached[2];
    ret.stoken = cached[3];
    ret.item = EncryptedCollectionItem.cacheLoad(cached[4]);

    return ret;
  }

  public cacheSave(saveContent: boolean) {
    return msgpackEncode([
      1, // Cache version format
      this.collectionKey,
      this.accessLevel,
      this.stoken,

      this.item.cacheSave(saveContent),
    ]);
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

  public async getMeta(cryptoManager: CollectionCryptoManager): Promise<CollectionMetadata> {
    this.verify(cryptoManager);
    const itemCryptoManager = this.item.getCryptoManager(cryptoManager);
    return this.item.getMeta(itemCryptoManager) as Promise<CollectionMetadata>;
  }

  public async setContent(cryptoManager: CollectionCryptoManager, content: Uint8Array): Promise<void> {
    const itemCryptoManager = this.item.getCryptoManager(cryptoManager);
    return this.item.setContent(itemCryptoManager, content);
  }

  public async getContent(cryptoManager: CollectionCryptoManager): Promise<Uint8Array> {
    this.verify(cryptoManager);
    const itemCryptoManager = this.item.getCryptoManager(cryptoManager);
    return this.item.getContent(itemCryptoManager);
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

  public get lastEtag() {
    return this.item.lastEtag;
  }

  public get version() {
    return this.item.version;
  }


  public async createInvitation(parentCryptoManager: AccountCryptoManager, identCryptoManager: BoxCryptoManager, username: string, pubkey: Uint8Array, accessLevel: CollectionAccessLevel): Promise<SignedInvitationWrite> {
    const uid = randomBytes(32);
    const encryptionKey = parentCryptoManager.decrypt(this.collectionKey);
    const signedEncryptionKey = identCryptoManager.encrypt(encryptionKey, pubkey);
    const ret: SignedInvitationWrite = {
      version: Constants.CURRENT_VERSION,
      uid: toBase64(uid),
      username,
      collection: this.uid,
      accessLevel,

      signedEncryptionKey: signedEncryptionKey,
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

  public lastEtag: string | null;

  public static async create(parentCryptoManager: CollectionCryptoManager, meta: ItemMetadata, content: Uint8Array): Promise<EncryptedCollectionItem> {
    const ret = new EncryptedCollectionItem();
    ret.uid = genUidBase64();
    ret.version = Constants.CURRENT_VERSION;
    ret.encryptionKey = null;

    ret.lastEtag = null;

    const cryptoManager = ret.getCryptoManager(parentCryptoManager);

    ret.content = await EncryptedRevision.create(cryptoManager, ret.getAdditionalMacData(), meta, content);

    return ret;
  }

  public static deserialize(json: CollectionItemJsonRead): EncryptedCollectionItem {
    const { uid, version, encryptionKey, content } = json;
    const ret = new EncryptedCollectionItem();
    ret.uid = uid;
    ret.version = version;
    ret.encryptionKey = encryptionKey ?? null;

    ret.content = EncryptedRevision.deserialize(content);

    ret.lastEtag = ret.content.uid;

    return ret;
  }

  public serialize() {
    const ret: CollectionItemJsonWrite = {
      uid: this.uid,
      version: this.version,
      encryptionKey: this.encryptionKey ?? undefined,
      etag: this.lastEtag,

      content: this.content.serialize(),
    };

    return ret;
  }

  public static cacheLoad(cached_: Uint8Array) {
    const cached = msgpackDecode(cached_) as any[];

    const ret = new EncryptedCollectionItem();
    ret.uid = toBase64(cached[1]);
    ret.version = cached[2];
    ret.encryptionKey = cached[3];
    ret.lastEtag = (cached[4]) ? toBase64(cached[4]) : null;

    ret.content = EncryptedRevision.cacheLoad(cached[5]);

    return ret;
  }

  public cacheSave(saveContent: boolean) {
    return msgpackEncode([
      1, // Cache version format
      fromBase64(this.uid),
      this.version,
      this.encryptionKey,
      (this.lastEtag) ? fromBase64(this.lastEtag) : null,

      this.content.cacheSave(saveContent),
    ]);
  }

  public __markSaved() {
    this.lastEtag = this.content.uid;
  }

  public __getPendingChunks(): ChunkJson[] {
    return this.content.chunks;
  }

  public __getMissingChunks(): ChunkJson[] {
    return this.content.chunks.filter(([_uid, content]) => !content);
  }

  private isLocallyChanged() {
    return this.lastEtag !== this.content.uid;
  }

  public async verify(cryptoManager: CollectionItemCryptoManager) {
    return this.content.verify(cryptoManager, this.getAdditionalMacData());
  }

  public async setMeta(cryptoManager: CollectionItemCryptoManager, meta: ItemMetadata): Promise<void> {
    let rev = this.content;
    if (!this.isLocallyChanged()) {
      rev = this.content.clone();
    }
    await rev.setMeta(cryptoManager, this.getAdditionalMacData(), meta);

    this.content = rev;
  }

  public async getMeta(cryptoManager: CollectionItemCryptoManager): Promise<ItemMetadata> {
    this.verify(cryptoManager);
    return this.content.getMeta(cryptoManager, this.getAdditionalMacData());
  }

  public async setContent(cryptoManager: CollectionItemCryptoManager, content: Uint8Array): Promise<void> {
    let rev = this.content;
    if (!this.isLocallyChanged()) {
      rev = this.content.clone();
    }
    await rev.setContent(cryptoManager, this.getAdditionalMacData(), content);

    this.content = rev;
  }

  public async getContent(cryptoManager: CollectionItemCryptoManager): Promise<Uint8Array> {
    this.verify(cryptoManager);
    return this.content.getContent(cryptoManager);
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

  public get etag() {
    return this.content.uid;
  }

  public get isMissingContent() {
    return this.content.chunks.some(([_uid, content]) => !content);
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

