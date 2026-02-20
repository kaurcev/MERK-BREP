import { IConnection, IClientRepository, IServerPeerRepository, ILogger } from '../core/types';
import { Frame, MsgType } from '../../shared/protocol';
import { ClientLocationService } from '../services/ClientLocationService';

export class DataHandler {
  constructor(
    private clientRepo: IClientRepository,
    private serverRepo: IServerPeerRepository,
    private locationService: ClientLocationService,
    private logger: ILogger
  ) {}

  async handle(connection: IConnection, frame: Frame): Promise<void> {
    const senderClient = this.clientRepo.getByConnection(connection);
    const senderServer = this.serverRepo.getByConnection(connection);
    if (!senderClient && !senderServer) {
      this.logger.warn(`[Received DATA from unauthenticated connection]: ${connection.id}`);
      connection.close();
      return;
    }

    if (frame.payload.length < 32) {
      this.logger.warn(`[Invalid DATA payload length] [from]: ${connection.id}`);
      return;
    }

    const targetKey = frame.payload.slice(0, 32);
    const targetHex = Buffer.from(targetKey).toString('hex');
    const targetClient = this.clientRepo.get(targetHex);

    if (targetClient) {
      this.logger.debug(`[Delivering DATA to local client] ${targetHex.slice(0,8)}`);
      targetClient.connection.send({
        type: MsgType.DATA,
        payload: frame.payload.slice(32),
        senderId: frame.senderId,
      });
      return;
    }

    this.logger.debug(`[Client ${targetHex.slice(0,8)} not local, querying...]`);
    await this.locationService.forwardToRemoteClient(targetKey, frame, senderClient || senderServer);
  }
}