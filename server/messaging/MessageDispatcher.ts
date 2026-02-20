import { IConnection, ILogger } from '../core/types';
import { Frame, MsgType } from '../../shared/protocol';
import { HandshakeHandler } from '../handlers/HandshakeHandler';
import { DataHandler } from '../handlers/DataHandler';
import { NodeInfoHandler } from '../handlers/NodeInfoHandler';

export class MessageDispatcher {
  constructor(
    private handshakeHandler: HandshakeHandler,
    private dataHandler: DataHandler,
    private nodeInfoHandler: NodeInfoHandler,
    private logger: ILogger
  ) {}

  async dispatch(connection: IConnection, frame: Frame): Promise<void> {
    try {
      switch (frame.type) {
        case MsgType.HANDSHAKE:
          await this.handshakeHandler.handle(connection, frame);
          break;
        case MsgType.DATA:
        case MsgType.SIGNED_DATA:
        case MsgType.ENCRYPTED_DATA:
          await this.dataHandler.handle(connection, frame);
          break;
        case MsgType.NODE_INFO:
          await this.nodeInfoHandler.handle(connection, frame);
          break;
        default:
          this.logger.warn(`Unknown frame type ${frame.type} from ${connection.id}`);
          connection.close();
      }
    } catch (err) {
      this.logger.error(`Error handling message from ${connection.id}:`, err);
      connection.close();
    }
  }
}