import { Frame, PublicKey } from '../../shared/protocol';

export interface IConnection {
  send(frame: Frame): void;
  close(): void;
  readonly id: string;
  readonly isOpen: boolean;
  peerType?: 'client' | 'server';
}

export interface IConnectionListener {
  onConnection(connection: IConnection): void;
}

export interface IConnectionManager {
  start(): void;
  stop(): void;
  registerListener(listener: IConnectionListener): void;
  unregisterListener(listener: IConnectionListener): void;
}

export interface IClientInfo {
  publicKey: PublicKey;
  connection: IConnection;
  authenticatedAt: Date;
}

export interface IServerPeerInfo {
  publicKey: PublicKey;
  address: string;
  connection?: IConnection;
}

export interface IClientRepository {
  add(client: IClientInfo): void;
  remove(publicKeyHex: string): void;
  get(publicKeyHex: string): IClientInfo | undefined;
  has(publicKeyHex: string): boolean;
  getAll(): IterableIterator<IClientInfo>;
  getByConnection(connection: IConnection): IClientInfo | undefined;
}

export interface IServerPeerRepository {
  add(peer: IServerPeerInfo): void;
  remove(publicKeyHex: string): void;
  get(publicKeyHex: string): IServerPeerInfo | undefined;
  has(publicKeyHex: string): boolean;
  getAll(): IterableIterator<IServerPeerInfo>;
  getByConnection(connection: IConnection): IServerPeerInfo | undefined;
}

export interface ILogger {
  info(...args: any[]): void;
  warn(...args: any[]): void;
  error(...args: any[]): void;
  debug(...args: any[]): void;
}
