import { WebSocketServerAdapter } from './websocket/WebSocketServerAdapter';
import { InMemoryClientRepository } from './repositories/InMemoryClientRepository';
import { InMemoryServerPeerRepository } from './repositories/InMemoryServerPeerRepository';
import { HandshakeHandler } from './handlers/HandshakeHandler';
import { DataHandler } from './handlers/DataHandler';
import { NodeInfoHandler } from './handlers/NodeInfoHandler';
import { MessageDispatcher } from './messaging/MessageDispatcher';
import { ClientLocationService } from './services/ClientLocationService';
import { ServerPeerService } from './services/ServerPeerService';
import { IConnection, IConnectionListener, ILogger } from './core/types';
import { generateKeyPairFromSeed } from '@stablelib/ed25519';
import { randomBytes } from 'crypto';
import { Config } from './config';
import { MsgType } from '../shared/protocol'; // <-- добавлен импорт

export class RelayServer implements IConnectionListener {
  private clientRepo = new InMemoryClientRepository();
  private serverRepo = new InMemoryServerPeerRepository();
  private serverPrivateKey: Uint8Array;
  private serverPublicKey: Uint8Array;

  private handshakeHandler: HandshakeHandler;
  private dataHandler: DataHandler;
  private nodeInfoHandler: NodeInfoHandler;
  private messageDispatcher: MessageDispatcher;
  private clientLocationService: ClientLocationService;
  private serverPeerService: ServerPeerService;
  private connectionManager: WebSocketServerAdapter;

  constructor(private config: Config, private logger: ILogger) {
    const seed = randomBytes(32);
    const keyPair = generateKeyPairFromSeed(seed);
    this.serverPrivateKey = keyPair.secretKey;
    this.serverPublicKey = keyPair.publicKey;
    this.logger.info(`Server public key: ${Buffer.from(this.serverPublicKey).toString('hex')}`);
    this.handshakeHandler = new HandshakeHandler(
      this.clientRepo,
      this.serverRepo,
      this.serverPrivateKey,
      this.serverPublicKey,
      this.logger
    );

    this.serverPeerService = new ServerPeerService(
      this.serverRepo,
      null as any,
      this.handshakeHandler,
      this.serverPublicKey,
      this.logger,
      this.config.port
    );

    this.clientLocationService = new ClientLocationService(
      this.serverRepo,
      this.serverPeerService,
      this.serverPublicKey,
      this.logger
    );

    this.dataHandler = new DataHandler(
      this.clientRepo,
      this.serverRepo,
      this.clientLocationService,
      this.logger
    );

    this.nodeInfoHandler = new NodeInfoHandler(
      this.clientRepo,
      this.serverRepo,
      this.serverPeerService,
      this.clientLocationService,
      this.serverPublicKey,
      this.logger
    );

    this.messageDispatcher = new MessageDispatcher(
      this.handshakeHandler,
      this.dataHandler,
      this.nodeInfoHandler,
      this.logger
    );

    this.serverPeerService.setMessageDispatcher(this.messageDispatcher);
    this.connectionManager = new WebSocketServerAdapter(this.config.port, this.messageDispatcher, this.logger);
    this.connectionManager.registerListener(this);
  }

  async start(): Promise<void> {
    this.connectionManager.start();
    for (const peerAddress of this.config.seedPeers) {
      try {
        await this.serverPeerService.connectToPeer(peerAddress);
      } catch (err) {
        this.logger.error(`Failed to connect to seed peer ${peerAddress}:`, err);
      }
    }
  }

  async stop(): Promise<void> {
    this.connectionManager.stop();
  }

  onConnection(connection: IConnection): void {
    const challenge = randomBytes(32);
    this.handshakeHandler.setPendingChallenge(connection, challenge);
    connection.send({
      type: MsgType.HANDSHAKE,
      payload: new Uint8Array(challenge),
      senderId: new Uint8Array(32),
    });
    this.logger.debug(`Sent challenge to new connection ${connection.id}`);
  }
}