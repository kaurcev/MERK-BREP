import { generateKeyPairFromSeed, sign, verify } from '@stablelib/ed25519';
import { generateKeyPairFromSeed as generateX25519KeyPairFromSeed, sharedKey } from '@stablelib/x25519';
import { hash } from '@stablelib/sha256';
import { PublicKey, PrivateKey, Signature, HexString, EncryptionPublicKey, EncryptionPrivateKey } from './types';
import { IStorage } from './storage';

export interface IKeyManager {
  getPublicKey(): PublicKey;
  getPublicKeyHex(): HexString;
  sign(data: Uint8Array): Signature;
  verify(publicKey: PublicKey, data: Uint8Array, signature: Signature): boolean;
  getEncryptionPublicKey(): EncryptionPublicKey;
  encryptFor(recipientPublicKey: EncryptionPublicKey, data: Uint8Array): Promise<Uint8Array>;
  decryptFrom(senderPublicKey: PublicKey, encryptedPackage: Uint8Array): Promise<Uint8Array>;
  exportKeys(): { publicKey: string; privateKey: string; encryptionPublicKey: string; encryptionPrivateKey: string };
  importKeys(keys: { publicKey: string; privateKey: string; encryptionPublicKey: string; encryptionPrivateKey: string }): Promise<void>;
  load(): Promise<void>;
}

function arrayToBase64(arr: Uint8Array): string {
  return btoa(String.fromCharCode(...arr));
}

function base64ToArray(base64: string): Uint8Array {
  return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}

export class Ed25519KeyManager implements IKeyManager {
  private signingPrivateKey: PrivateKey | null = null;
  private signingPublicKey: PublicKey | null = null;
  private encryptionPrivateKey: EncryptionPrivateKey | null = null;
  private encryptionPublicKey: EncryptionPublicKey | null = null;
  private readonly storagePrefix: string;

  constructor(private storage: IStorage, storagePrefix = 'sdk') {
    this.storagePrefix = storagePrefix;
  }

  async load(): Promise<void> {
    const [savedSignPrivate, savedSignPublic, savedEncPrivate, savedEncPublic] = await Promise.all([
      this.storage.getItem(`${this.storagePrefix}:privateKey`),
      this.storage.getItem(`${this.storagePrefix}:publicKey`),
      this.storage.getItem(`${this.storagePrefix}:encPrivateKey`),
      this.storage.getItem(`${this.storagePrefix}:encPublicKey`)
    ]);

    let generated = false;

    if (savedSignPrivate && savedSignPublic) {
      this.signingPrivateKey = new Uint8Array(JSON.parse(savedSignPrivate));
      this.signingPublicKey = new Uint8Array(JSON.parse(savedSignPublic));
    } else {
      const seed = new Uint8Array(32);
      crypto.getRandomValues(seed);
      const keyPair = generateKeyPairFromSeed(seed);
      this.signingPrivateKey = keyPair.secretKey;
      this.signingPublicKey = keyPair.publicKey;
      generated = true;
    }

    if (savedEncPrivate && savedEncPublic) {
      this.encryptionPrivateKey = new Uint8Array(JSON.parse(savedEncPrivate));
      this.encryptionPublicKey = new Uint8Array(JSON.parse(savedEncPublic));
    } else {
      const seed = new Uint8Array(32);
      crypto.getRandomValues(seed);
      const keyPair = generateX25519KeyPairFromSeed(seed);
      this.encryptionPrivateKey = keyPair.secretKey;
      this.encryptionPublicKey = keyPair.publicKey;
      generated = true;
    }

    if (generated) {
      await this.saveKeys();
    }
  }

  private async saveKeys(): Promise<void> {
    const promises = [];
    if (this.signingPrivateKey && this.signingPublicKey) {
      promises.push(this.storage.setItem(`${this.storagePrefix}:privateKey`, JSON.stringify(Array.from(this.signingPrivateKey))));
      promises.push(this.storage.setItem(`${this.storagePrefix}:publicKey`, JSON.stringify(Array.from(this.signingPublicKey))));
    }
    if (this.encryptionPrivateKey && this.encryptionPublicKey) {
      promises.push(this.storage.setItem(`${this.storagePrefix}:encPrivateKey`, JSON.stringify(Array.from(this.encryptionPrivateKey))));
      promises.push(this.storage.setItem(`${this.storagePrefix}:encPublicKey`, JSON.stringify(Array.from(this.encryptionPublicKey))));
    }
    await Promise.all(promises);
  }

  getPublicKey(): PublicKey {
    if (!this.signingPublicKey) throw new Error('[KeyManager not loaded]');
    return this.signingPublicKey.slice();
  }

  getPublicKeyHex(): HexString {
    if (!this.signingPublicKey) throw new Error('[KeyManager not loaded]');
    return Array.from(this.signingPublicKey).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  sign(data: Uint8Array): Signature {
    if (!this.signingPrivateKey) throw new Error('[KeyManager not loaded]');
    return sign(this.signingPrivateKey, data);
  }

  verify(publicKey: PublicKey, data: Uint8Array, signature: Signature): boolean {
    try {
      return verify(publicKey, data, signature);
    } catch {
      return false;
    }
  }

  getEncryptionPublicKey(): EncryptionPublicKey {
    if (!this.encryptionPublicKey) throw new Error('[KeyManager not loaded]');
    return this.encryptionPublicKey.slice();
  }

  async encryptFor(recipientPublicKey: EncryptionPublicKey, data: Uint8Array): Promise<Uint8Array> {
    if (!this.encryptionPrivateKey) throw new Error('[KeyManager not loaded]');

    const ephemeralSeed = new Uint8Array(32);
    crypto.getRandomValues(ephemeralSeed);
    const ephemeralKeyPair = generateX25519KeyPairFromSeed(ephemeralSeed);
    const sharedSecret = sharedKey(ephemeralKeyPair.secretKey, recipientPublicKey);
    const keyMaterial = hash(sharedSecret);
    const keyMaterialCopy = new Uint8Array(keyMaterial);

    const aesKey = await crypto.subtle.importKey(
      'raw',
      keyMaterialCopy,
      { name: 'AES-GCM' },
      false,
      ['encrypt']
    );

    const nonce = new Uint8Array(12);
    crypto.getRandomValues(nonce);

    const dataCopy = new Uint8Array(data);

    const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce },
      aesKey,
      dataCopy
    ));

    const result = new Uint8Array(32 + 12 + ciphertext.length);
    result.set(ephemeralKeyPair.publicKey, 0);
    result.set(nonce, 32);
    result.set(ciphertext, 32 + 12);
    return result;
  }

  async decryptFrom(senderPublicKey: PublicKey, encryptedPackage: Uint8Array): Promise<Uint8Array> {
    if (!this.encryptionPrivateKey) throw new Error('[KeyManager not loaded]');
    if (encryptedPackage.length < 32 + 12) throw new Error('[Invalid encrypted package]');

    const ephemeralPublicKey = encryptedPackage.slice(0, 32);
    const nonce = encryptedPackage.slice(32, 32 + 12);
    const ciphertext = encryptedPackage.slice(32 + 12);

    const sharedSecret = sharedKey(this.encryptionPrivateKey, ephemeralPublicKey);
    const keyMaterial = hash(sharedSecret);
    const keyMaterialCopy = new Uint8Array(keyMaterial);

    const aesKey = await crypto.subtle.importKey(
      'raw',
      keyMaterialCopy,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce },
      aesKey,
      ciphertext
    );

    return new Uint8Array(plaintext);
  }

  exportKeys(): { publicKey: string; privateKey: string; encryptionPublicKey: string; encryptionPrivateKey: string } {
    if (!this.signingPublicKey || !this.signingPrivateKey || !this.encryptionPublicKey || !this.encryptionPrivateKey) {
      throw new Error('[KeyManager not loaded]');
    }
    return {
      publicKey: arrayToBase64(this.signingPublicKey),
      privateKey: arrayToBase64(this.signingPrivateKey),
      encryptionPublicKey: arrayToBase64(this.encryptionPublicKey),
      encryptionPrivateKey: arrayToBase64(this.encryptionPrivateKey)
    };
  }

  async importKeys(keys: { publicKey: string; privateKey: string; encryptionPublicKey: string; encryptionPrivateKey: string }): Promise<void> {
    this.signingPublicKey = base64ToArray(keys.publicKey);
    this.signingPrivateKey = base64ToArray(keys.privateKey);
    this.encryptionPublicKey = base64ToArray(keys.encryptionPublicKey);
    this.encryptionPrivateKey = base64ToArray(keys.encryptionPrivateKey);

    if (this.signingPublicKey.length !== 32 || this.signingPrivateKey.length !== 64 ||
        this.encryptionPublicKey.length !== 32 || this.encryptionPrivateKey.length !== 32) {
      throw new Error('[Invalid key length]');
    }

    await this.saveKeys();
  }
}