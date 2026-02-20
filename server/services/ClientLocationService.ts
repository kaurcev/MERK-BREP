import { Frame, MsgType, NODE_INFO_QUERY_CLIENT, PublicKey } from '../../shared/protocol';
import { IServerPeerRepository, ILogger } from '../core/types';
import { ServerPeerService } from './ServerPeerService';

interface PendingQuery {
  frame: Frame;
  timer: NodeJS.Timeout;
  sender: any;
}

export class ClientLocationService {
  private pendingQueries = new Map<string, PendingQuery>();

  constructor(
    private serverRepo: IServerPeerRepository,
    private serverPeerService: ServerPeerService,
    private serverPublicKey: Uint8Array,
    private logger: ILogger
  ) {}

  async forwardToRemoteClient(targetKey: PublicKey, originalFrame: Frame, sender: any): Promise<void> {
    const targetHex = Buffer.from(targetKey).toString('hex');

    if (this.pendingQueries.has(targetHex)) {
      this.logger.debug(`Query already pending for ${targetHex.slice(0,8)}`);
      return;
    }

    const frameCopy: Frame = {
      type: originalFrame.type,
      payload: originalFrame.payload.slice(),
      senderId: originalFrame.senderId.slice(),
    };
    if (originalFrame.signature) {
      frameCopy.signature = originalFrame.signature.slice();
    }

    const timer = setTimeout(() => {
      this.pendingQueries.delete(targetHex);
      this.logger.warn(`Query for client ${targetHex.slice(0,8)} timed out`);
    }, 5000);

    this.pendingQueries.set(targetHex, { frame: frameCopy, timer, sender });

    const queryPayload = new Uint8Array(1 + 32);
    queryPayload[0] = NODE_INFO_QUERY_CLIENT;
    queryPayload.set(targetKey, 1);

    this.serverPeerService.broadcastToPeers({
      type: MsgType.NODE_INFO,
      payload: queryPayload,
      senderId: this.serverPublicKey,
    });
  }

  async handleQueryResponse(frame: Frame): Promise<void> {
    const payload = frame.payload;
    if (payload.length < 1 + 1 + 32) return;
    const status = payload[1];
    const targetKey = payload.slice(2, 2 + 32);
    const targetHex = Buffer.from(targetKey).toString('hex');

    const pending = this.pendingQueries.get(targetHex);
    if (!pending) {
      this.logger.debug(`Received query response for unknown pending ${targetHex.slice(0,8)}`);
      return;
    }

    clearTimeout(pending.timer);
    this.pendingQueries.delete(targetHex);

    if (status === 1 && payload.length >= 1 + 1 + 32 + 32) {
      const serverKey = payload.slice(2 + 32, 2 + 32 + 32);
      const serverHex = Buffer.from(serverKey).toString('hex');
      const targetServer = this.serverRepo.get(serverHex);
      if (targetServer?.connection) {
        this.logger.debug(`Forwarding DATA to server ${serverHex.slice(0,8)} for client ${targetHex.slice(0,8)}`);
        targetServer.connection.send({
          type: MsgType.DATA,
          payload: pending.frame.payload,
          senderId: pending.frame.senderId,
        });
      } else {
        this.logger.warn(`Target server ${serverHex.slice(0,8)} not connected`);
      }
    } else {
      this.logger.debug(`Client ${targetHex.slice(0,8)} not found on any peer`);
    }
  }
}