import { IStorage } from './storage';
import { TypedEventEmitter, EventMap } from './events';

export interface ServerManagerEvents extends EventMap {
  listChanged: [servers: string[]];
  selectedChanged: [server: string | null];
}

export interface IServerManager {
  getServers(): Promise<string[]>;
  addServer(address: string): Promise<void>;
  removeServer(address: string): Promise<void>;
  setSelectedServer(address: string | null): Promise<void>;
  getSelectedServer(): Promise<string | null>;
  on<K extends keyof ServerManagerEvents>(event: K, listener: (...args: ServerManagerEvents[K]) => void): void;
  off<K extends keyof ServerManagerEvents>(event: K, listener: (...args: ServerManagerEvents[K]) => void): void;
}

export class LocalServerManager
  extends TypedEventEmitter<ServerManagerEvents>
  implements IServerManager
{
  private servers: string[] = [];
  private selected: string | null = null;
  private readonly storageKey = 'sdk:servers';
  private readonly selectedKey = 'sdk:selectedServer';
  private loaded = false;

  constructor(private storage: IStorage) {
    super();
  }

  private async ensureLoaded(): Promise<void> {
    if (this.loaded) return;
    const [saved, savedSelected] = await Promise.all([
      this.storage.getItem(this.storageKey),
      this.storage.getItem(this.selectedKey)
    ]);
    this.servers = saved ? JSON.parse(saved) : [];
    this.selected = savedSelected || null;
    this.loaded = true;
  }

  private async saveServers(): Promise<void> {
    await this.storage.setItem(this.storageKey, JSON.stringify(this.servers));
    this.emit('listChanged', this.servers.slice());
  }

  async getServers(): Promise<string[]> {
    await this.ensureLoaded();
    return this.servers.slice();
  }

  async addServer(address: string): Promise<void> {
    await this.ensureLoaded();
    if (!this.servers.includes(address)) {
      this.servers.push(address);
      await this.saveServers();
    }
  }

  async removeServer(address: string): Promise<void> {
    await this.ensureLoaded();
    const index = this.servers.indexOf(address);
    if (index !== -1) {
      this.servers.splice(index, 1);
      if (this.selected === address) {
        await this.setSelectedServer(this.servers[0] || null);
      }
      await this.saveServers();
    }
  }

  async setSelectedServer(address: string | null): Promise<void> {
    await this.ensureLoaded();
    if (address !== null && !this.servers.includes(address)) {
      throw new Error('[Server not in list]');
    }
    this.selected = address;
    if (address === null) {
      await this.storage.removeItem(this.selectedKey);
    } else {
      await this.storage.setItem(this.selectedKey, address);
    }
    this.emit('selectedChanged', address);
  }

  async getSelectedServer(): Promise<string | null> {
    await this.ensureLoaded();
    return this.selected;
  }
}