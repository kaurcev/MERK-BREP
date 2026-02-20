export interface IStorage {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
}

export class LocalStorageStorage implements IStorage {
  async getItem(key: string): Promise<string | null> {
    return Promise.resolve(localStorage.getItem(key));
  }
  async setItem(key: string, value: string): Promise<void> {
    localStorage.setItem(key, value);
    return Promise.resolve();
  }
  async removeItem(key: string): Promise<void> {
    localStorage.removeItem(key);
    return Promise.resolve();
  }
}

export class IndexedDBStorage implements IStorage {
  private db: IDBDatabase | null = null;
  private readonly dbName: string;
  private readonly storeName: string;

  constructor(dbName = 'exvia-sdk', storeName = 'keyval') {
    this.dbName = dbName;
    this.storeName = storeName;
  }

  private async openDB(): Promise<IDBDatabase> {
    if (this.db) return this.db;
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, 1);
      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        this.db = request.result;
        resolve(this.db);
      };
      request.onupgradeneeded = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;
        if (!db.objectStoreNames.contains(this.storeName)) {
          db.createObjectStore(this.storeName);
        }
      };
    });
  }

  private async withStore(mode: IDBTransactionMode, callback: (store: IDBObjectStore) => IDBRequest): Promise<any> {
    const db = await this.openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(this.storeName, mode);
      const store = tx.objectStore(this.storeName);
      const request = callback(store);
      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve(request.result);
      tx.oncomplete = () => resolve(request.result);
      tx.onerror = () => reject(tx.error);
    });
  }

  async getItem(key: string): Promise<string | null> {
    return this.withStore('readonly', store => store.get(key));
  }

  async setItem(key: string, value: string): Promise<void> {
    return this.withStore('readwrite', store => store.put(value, key));
  }

  async removeItem(key: string): Promise<void> {
    return this.withStore('readwrite', store => store.delete(key));
  }
}