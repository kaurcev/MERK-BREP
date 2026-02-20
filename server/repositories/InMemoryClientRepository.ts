import { IClientRepository, IClientInfo } from '../core/types';

export class InMemoryClientRepository implements IClientRepository {
  private clients = new Map<string, IClientInfo>();
  private connectionToKey = new Map<IClientInfo['connection'], string>();

  add(client: IClientInfo): void {
    const key = Buffer.from(client.publicKey).toString('hex');
    this.clients.set(key, client);
    this.connectionToKey.set(client.connection, key);
  }

  remove(publicKeyHex: string): void {
    const client = this.clients.get(publicKeyHex);
    if (client) {
      this.connectionToKey.delete(client.connection);
      this.clients.delete(publicKeyHex);
    }
  }

  get(publicKeyHex: string): IClientInfo | undefined {
    return this.clients.get(publicKeyHex);
  }

  has(publicKeyHex: string): boolean {
    return this.clients.has(publicKeyHex);
  }

  getAll(): IterableIterator<IClientInfo> {
    return this.clients.values();
  }

  getByConnection(connection: IClientInfo['connection']): IClientInfo | undefined {
    const key = this.connectionToKey.get(connection);
    return key ? this.clients.get(key) : undefined;
  }
}