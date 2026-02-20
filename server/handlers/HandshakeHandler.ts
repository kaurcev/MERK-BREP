import { IConnection, IClientRepository, IServerPeerRepository, ILogger } from '../core/types';
import { Frame, MsgType, PublicKey } from '../../shared/protocol';
import { sign, verify } from '@stablelib/ed25519';

export class HandshakeHandler {
  private pendingChallenges = new Map<IConnection, Buffer>();

  constructor(
    private clientRepo: IClientRepository,
    private serverRepo: IServerPeerRepository,
    private serverPrivateKey: Uint8Array,
    private serverPublicKey: PublicKey,
    private logger: ILogger
  ) {}

  public setPendingChallenge(connection: IConnection, challenge: Buffer): void {
    this.pendingChallenges.set(connection, challenge);
  }

  async handle(connection: IConnection, frame: Frame): Promise<void> {
    this.logger.info(`[Handshake] Received frame from ${connection.id}, type: ${frame.type}, payload length: ${frame.payload.length}, has sig: ${!!frame.signature}`);

    if (frame.payload.length === 32 && !frame.signature) {
      await this.handleIncomingChallenge(connection, frame);
    }
    else if (frame.payload.length === 32 && frame.signature) {
      await this.handleAuthentication(connection, frame);
    }
    else if (frame.payload.length === 1 && frame.payload[0] === 1) {
      await this.handleHandshakeConfirm(connection, frame);
    }
    else {
      this.logger.warn(`Unexpected handshake frame from ${connection.id}`);
      connection.close();
    }
  }

  private async handleIncomingChallenge(connection: IConnection, frame: Frame): Promise<void> {
    this.logger.info(`[Handshake] Incoming challenge from ${connection.id}`);
    const signature = sign(this.serverPrivateKey, frame.payload);
    connection.send({
      type: MsgType.HANDSHAKE,
      payload: frame.payload,
      senderId: this.serverPublicKey,
      signature,
    });
    this.logger.info(`[Handshake] Sent signed challenge response to ${connection.id}`);
  }

  private async handleAuthentication(connection: IConnection, frame: Frame): Promise<void> {
    this.logger.info(`[Handshake] Received authentication from ${connection.id}`);
    const publicKey = frame.senderId;
    const isValid = verify(publicKey, frame.payload, frame.signature!);
    if (!isValid) {
      this.logger.warn(`[Handshake] Invalid signature from ${connection.id}`);
      connection.close();
      return;
    }
    this.logger.info(`[Handshake] Signature valid for ${connection.id}`);

    const publicKeyHex = Buffer.from(publicKey).toString('hex');
    const expectedChallenge = this.pendingChallenges.get(connection);

    if (connection.peerType === 'server') {
      if (!expectedChallenge || !Buffer.from(frame.payload).equals(expectedChallenge)) {
        this.logger.warn(`[Handshake] Challenge mismatch for outgoing server ${publicKeyHex.slice(0,8)}`);
        connection.close();
        return;
      }
      this.pendingChallenges.delete(connection);

      const existing = this.serverRepo.get(publicKeyHex);
      if (existing && existing.connection) {
        this.logger.info(`[Handshake] Server ${publicKeyHex.slice(0,8)} reconnecting, closing old connection`);
        existing.connection.close();
      }

      let peer = this.serverRepo.get(publicKeyHex);
      if (!peer) {
        peer = { publicKey, address: 'unknown', connection };
      } else {
        peer.connection = connection;
      }
      this.serverRepo.add(peer);
      this.logger.info(`[Handshake] Outgoing server ${publicKeyHex.slice(0,8)} authenticated`);
      connection.send({
        type: MsgType.HANDSHAKE,
        payload: new Uint8Array([1]),
        senderId: this.serverPublicKey,
      });
      this.logger.info(`[Handshake] Sent confirmation to outgoing server ${connection.id}`);
    } else {
      if (!expectedChallenge) {
        this.logger.warn(`[Handshake] No pending challenge for connection ${connection.id}`);
        connection.close();
        return;
      }
      if (!Buffer.from(frame.payload).equals(expectedChallenge)) {
        this.logger.warn(`[Handshake] Challenge mismatch for incoming connection ${publicKeyHex.slice(0,8)}`);
        connection.close();
        return;
      }
      this.pendingChallenges.delete(connection);
      const existingServer = this.serverRepo.get(publicKeyHex);
      if (existingServer) {
        if (existingServer.connection) {
          this.logger.info(`[Handshake] Incoming server ${publicKeyHex.slice(0,8)} reconnecting, closing old connection`);
          existingServer.connection.close();
        }
        existingServer.connection = connection;
        this.serverRepo.add(existingServer);
        connection.peerType = 'server';
        this.logger.info(`[Handshake] Incoming server ${publicKeyHex.slice(0,8)} authenticated`);
        connection.send({
          type: MsgType.HANDSHAKE,
          payload: new Uint8Array([1]),
          senderId: this.serverPublicKey,
        });
        this.logger.info(`[Handshake] Sent confirmation to incoming server ${connection.id}`);
      } else {
        const existingClient = this.clientRepo.get(publicKeyHex);
        if (existingClient) {
          this.logger.info(`[Handshake] Client ${publicKeyHex.slice(0,8)} reconnecting, closing old connection`);
          existingClient.connection.close();
          this.clientRepo.remove(publicKeyHex);
        }
        const clientInfo = {
          publicKey,
          connection,
          authenticatedAt: new Date(),
        };
        this.clientRepo.add(clientInfo);
        connection.peerType = 'client';
        this.logger.info(`[Handshake] Client ${publicKeyHex.slice(0,8)} authenticated`);
        connection.send({
          type: MsgType.HANDSHAKE,
          payload: new Uint8Array([1]),
          senderId: this.serverPublicKey,
        });
        this.logger.info(`[Handshake] Sent confirmation to client ${connection.id}`);
      }
    }
  }

  private async handleHandshakeConfirm(connection: IConnection, frame: Frame): Promise<void> {
    this.logger.debug(`[Handshake] Confirm from ${connection.id}`);
  }
}