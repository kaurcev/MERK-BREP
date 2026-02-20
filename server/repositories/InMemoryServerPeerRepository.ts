import { IServerPeerRepository, IServerPeerInfo } from '../core/types';

export class InMemoryServerPeerRepository implements IServerPeerRepository {
  private peers = new Map<string, IServerPeerInfo>();
  private connectionToKey = new Map<IServerPeerInfo['connection'], string>();

  add(peer: IServerPeerInfo): void {
    const key = Buffer.from(peer.publicKey).toString('hex');
    this.peers.set(key, peer);
    if (peer.connection) {
      this.connectionToKey.set(peer.connection, key);
    }
  }

  remove(publicKeyHex: string): void {
    const peer = this.peers.get(publicKeyHex);
    if (peer) {
      if (peer.connection) {
        this.connectionToKey.delete(peer.connection);
      }
      this.peers.delete(publicKeyHex);
    }
  }

  get(publicKeyHex: string): IServerPeerInfo | undefined {
    return this.peers.get(publicKeyHex);
  }

  has(publicKeyHex: string): boolean {
    return this.peers.has(publicKeyHex);
  }

  getAll(): IterableIterator<IServerPeerInfo> {
    return this.peers.values();
  }

  getByConnection(connection: IServerPeerInfo['connection']): IServerPeerInfo | undefined {
    const key = this.connectionToKey.get(connection);
    return key ? this.peers.get(key) : undefined;
  }
}