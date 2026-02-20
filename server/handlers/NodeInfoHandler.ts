import { IConnection, IClientRepository, IServerPeerRepository, ILogger } from '../core/types';
import { Frame, MsgType, NODE_INFO_REQUEST_SERVERS, NODE_INFO_RESPONSE_SERVERS, NODE_INFO_ADD_SERVER, NODE_INFO_QUERY_CLIENT, NODE_INFO_QUERY_RESPONSE } from '../../shared/protocol';
import { ServerPeerService } from '../services/ServerPeerService';
import { ClientLocationService } from '../services/ClientLocationService';

export class NodeInfoHandler {
  constructor(
    private clientRepo: IClientRepository,
    private serverRepo: IServerPeerRepository,
    private serverPeerService: ServerPeerService,
    private locationService: ClientLocationService,
    private serverPublicKey: Uint8Array,
    private logger: ILogger
  ) {}

  async handle(connection: IConnection, frame: Frame): Promise<void> {
    const senderClient = this.clientRepo.getByConnection(connection);
    const senderServer = this.serverRepo.getByConnection(connection);
    if (!senderClient && !senderServer) {
      this.logger.warn(`Received NODE_INFO from unauthenticated connection ${connection.id}`);
      connection.close();
      return;
    }

    const payload = frame.payload;
    if (payload.length === 0) return;
    const subType = payload[0];

    switch (subType) {
      case NODE_INFO_REQUEST_SERVERS:
        await this.handleRequestServers(connection, frame);
        break;
      case NODE_INFO_RESPONSE_SERVERS:
        await this.handleResponseServers(connection, frame);
        break;
      case NODE_INFO_ADD_SERVER:
        await this.handleAddServer(connection, frame, senderClient, senderServer);
        break;
      case NODE_INFO_QUERY_CLIENT:
        await this.handleQueryClient(connection, frame);
        break;
      case NODE_INFO_QUERY_RESPONSE:
        await this.handleQueryResponse(connection, frame);
        break;
      default:
        this.logger.warn(`Unknown NODE_INFO subtype ${subType} from ${connection.id}`);
    }
  }

  private async handleRequestServers(connection: IConnection, frame: Frame): Promise<void> {
    const servers: { publicKey: Uint8Array; address: string }[] = [];
    for (const peer of this.serverRepo.getAll()) {
      if (peer.address && peer.address !== 'unknown') {
        servers.push({ publicKey: peer.publicKey, address: peer.address });
      }
    }

    let totalLength = 1 + 2;
    const chunks: Buffer[] = [];
    for (const s of servers) {
      const addrBuf = Buffer.from(s.address, 'utf8');
      totalLength += 32 + 1 + addrBuf.length;
      chunks.push(Buffer.from(s.publicKey));
      chunks.push(Buffer.from([addrBuf.length]));
      chunks.push(addrBuf);
    }
    const payload = Buffer.alloc(totalLength);
    payload[0] = NODE_INFO_RESPONSE_SERVERS;
    payload.writeUInt16BE(servers.length, 1);
    let offset = 3;
    for (const chunk of chunks) {
      chunk.copy(payload, offset);
      offset += chunk.length;
    }
    connection.send({
      type: MsgType.NODE_INFO,
      payload: new Uint8Array(payload),
      senderId: this.serverPublicKey,
    });
  }

  private async handleResponseServers(connection: IConnection, frame: Frame): Promise<void> {
    const senderServer = this.serverRepo.getByConnection(connection);
    if (!senderServer) return;

    const payload = Buffer.from(frame.payload);
    if (payload.length < 3) return;
    const count = payload.readUInt16BE(1);
    let offset = 3;
    for (let i = 0; i < count; i++) {
      if (offset + 32 > payload.length) break;
      const pubKey = payload.slice(offset, offset + 32);
      offset += 32;
      if (offset >= payload.length) break;
      const addrLen = payload[offset];
      if (addrLen === undefined) break;
      offset += 1;
      if (offset + addrLen > payload.length) break;
      const addrBytes = payload.slice(offset, offset + addrLen);
      const addr = addrBytes.toString('utf8');
      offset += addrLen;

      const pubKeyHex = pubKey.toString('hex');
      if (!this.serverRepo.has(pubKeyHex) && !pubKey.equals(this.serverPublicKey)) {
        this.logger.info(`Discovered new server: ${addr} (${pubKeyHex.slice(0,8)})`);
        this.serverRepo.add({
          publicKey: new Uint8Array(pubKey),
          address: addr,
        });
        this.serverPeerService.connectToPeer(addr).catch(err => {
          this.logger.error(`Failed to connect to discovered server ${addr}:`, err);
        });
      }
    }
  }

  private async handleAddServer(connection: IConnection, frame: Frame, senderClient?: any, senderServer?: any): Promise<void> {
    if (!senderClient && !senderServer) return;
    const payload = frame.payload;
    if (payload.length < 2) return;
    const addrLen = payload[1];
    if (addrLen === undefined) return;
    if (payload.length < 2 + addrLen) return;
    const addressBytes = payload.slice(2, 2 + addrLen);
    const address = new TextDecoder().decode(addressBytes);

    for (const peer of this.serverRepo.getAll()) {
      if (peer.address === address) {
        this.logger.debug(`Server ${address} already known`);
        return;
      }
    }
    if (address === `ws://localhost:${this.serverPeerService.getPort()}`) {
      this.logger.debug(`Ignoring self address`);
      return;
    }

    this.logger.info(`Adding new server from ${senderClient ? 'client' : 'server'}: ${address}`);
    this.serverPeerService.connectToPeer(address).catch(err => {
      this.logger.error(`Failed to connect to added server ${address}:`, err);
    });
  }

  private async handleQueryClient(connection: IConnection, frame: Frame): Promise<void> {
    const payload = frame.payload;
    if (payload.length < 1 + 32) return;
    const targetKey = payload.slice(1, 33);
    const targetHex = Buffer.from(targetKey).toString('hex');
    const found = this.clientRepo.has(targetHex);
    this.logger.debug(`Query for client ${targetHex.slice(0,8)}: ${found ? 'found' : 'not found'}`);

    const responsePayload = found
      ? new Uint8Array(1 + 1 + 32 + 32)
      : new Uint8Array(1 + 1 + 32);
    responsePayload[0] = NODE_INFO_QUERY_RESPONSE;
    responsePayload[1] = found ? 1 : 0;
    responsePayload.set(targetKey, 2);
    if (found) {
      responsePayload.set(this.serverPublicKey, 2 + 32);
    }

    connection.send({
      type: MsgType.NODE_INFO,
      payload: responsePayload,
      senderId: this.serverPublicKey,
    });
  }

  private async handleQueryResponse(connection: IConnection, frame: Frame): Promise<void> {
    await this.locationService.handleQueryResponse(frame);
  }
}