import WebSocket from 'ws';
import { randomBytes } from 'crypto';
import { IConnection, IServerPeerRepository, ILogger } from '../core/types';
import { Frame, MsgType, PublicKey, decodeFrame } from '../../shared/protocol';
import { WebSocketConnection } from '../websocket/WebSocketConnection';
import { MessageDispatcher } from '../messaging/MessageDispatcher';
import { HandshakeHandler } from '../handlers/HandshakeHandler';

export class ServerPeerService {
  private messageDispatcher: MessageDispatcher;

  constructor(
    private serverRepo: IServerPeerRepository,
    messageDispatcher: MessageDispatcher,
    private handshakeHandler: HandshakeHandler, // добавлено
    private serverPublicKey: PublicKey,
    private logger: ILogger,
    private port: number
  ) {
    this.messageDispatcher = messageDispatcher;
  }

  setMessageDispatcher(dispatcher: MessageDispatcher) {
    this.messageDispatcher = dispatcher;
  }

  async connectToPeer(address: string): Promise<void> {
    for (const peer of this.serverRepo.getAll()) {
      if (peer.address === address && peer.connection) {
        this.logger.debug(`Already connected to peer ${address}`);
        return;
      }
    }

    this.logger.info(`Connecting to peer server: ${address}`);
    const ws = new WebSocket(address);
    ws.binaryType = 'arraybuffer';

    const connection = new WebSocketConnection(ws);
    connection.peerType = 'server';

    ws.onopen = () => {
      this.logger.debug(`WebSocket opened to ${address}`);
      const challenge = randomBytes(32);
      this.handshakeHandler.setPendingChallenge(connection, challenge);
      connection.send({
        type: MsgType.HANDSHAKE,
        payload: new Uint8Array(challenge),
        senderId: new Uint8Array(32),
      });
    };

    ws.onmessage = async (event) => {
      try {
        const frame = decodeFrame(event.data as ArrayBuffer);
        await this.messageDispatcher.dispatch(connection, frame);
      } catch (err) {
        this.logger.error(`Error handling peer message from ${address}:`, err);
      }
    };

    ws.onerror = (err) => {
      this.logger.error(`Peer connection error to ${address}:`, err);
    };

    ws.onclose = () => {
      this.logger.info(`Disconnected from peer ${address}`);
      for (const peer of this.serverRepo.getAll()) {
        if (peer.connection === connection) {
          this.serverRepo.remove(Buffer.from(peer.publicKey).toString('hex'));
          break;
        }
      }
    };
  }

  broadcastToPeers(frame: Frame, exclude?: IConnection): void {
    for (const peer of this.serverRepo.getAll()) {
      if (peer.connection && peer.connection !== exclude && peer.connection.isOpen) {
        peer.connection.send(frame);
      }
    }
  }

  getPort(): number {
    return this.port;
  }
}