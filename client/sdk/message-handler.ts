import { MsgType, NODE_INFO_ADD_SERVER, NODE_INFO_REQUEST_SERVERS, NODE_INFO_RESPONSE_SERVERS } from '../../shared/protocol';
import { Frame, PublicKey, ContentType } from './types';
import { IKeyManager } from './key-manager';
import { IConnectionManager } from './connection-manager';
import { IServerManager } from './server-manager';
import { TypedEventEmitter, EventMap } from './events';

export interface MessageHandlerEvents extends EventMap {
  handshakeSuccess: [];
  message: [from: PublicKey, content: Uint8Array, contentType?: ContentType, parsed?: any];
  nodeInfoAddServer: [address: string];
  serversListReceived: [addresses: string[]];
}

export interface IMessageHandler {
  handleFrame(frame: Frame): Promise<void>;
  sendData(target: PublicKey, payload: Uint8Array): void;
  sendSigned(target: PublicKey, content: Uint8Array, contentType?: ContentType): void;
  sendEncrypted(target: PublicKey, content: Uint8Array, recipientEncryptionKey: Uint8Array, contentType?: ContentType): Promise<void>;
  sendNodeInfoAddServer(address: string): void;
  sendRequestServers(): void;
  on<K extends keyof MessageHandlerEvents>(event: K, listener: (...args: MessageHandlerEvents[K]) => void): void;
  off<K extends keyof MessageHandlerEvents>(event: K, listener: (...args: MessageHandlerEvents[K]) => void): void;
  once<K extends keyof MessageHandlerEvents>(event: K, listener: (...args: MessageHandlerEvents[K]) => void): void;
}

export class MessageHandler
  extends TypedEventEmitter<MessageHandlerEvents>
  implements IMessageHandler
{
  private pendingChallenge: Uint8Array | null = null;
  private handshakeCompleted = false;

  constructor(
    private keyManager: IKeyManager,
    private connectionManager: IConnectionManager,
    private serverManager: IServerManager,
    private nick: string
  ) {
    super();
    this.connectionManager.on('frame', this.handleFrame.bind(this));
  }

  private isZeroSignature(sig: Uint8Array): boolean {
    return sig.every(b => b === 0);
  }

  async handleFrame(frame: Frame): Promise<void> {
    console.log('[Received frame] [type]:', frame.type, '[payload length]:', frame.payload.length);
    switch (frame.type) {
      case MsgType.HANDSHAKE:
        await this.handleHandshake(frame);
        break;
      case MsgType.DATA:
        this.handleData(frame);
        break;
      case MsgType.SIGNED_DATA:
        this.handleSignedData(frame);
        break;
      case MsgType.ENCRYPTED_DATA:
        await this.handleEncryptedData(frame);
        break;
      case MsgType.NODE_INFO:
        this.handleNodeInfo(frame);
        break;
      default:
        console.warn('Unknown frame type', frame.type);
    }
  }

  private async handleHandshake(frame: Frame): Promise<void> {
    console.log('[Handling handshake] [payload length]:', frame.payload.length, '[has signature]:', !!frame.signature, '[isZeroSig]:', this.isZeroSignature(frame.signature!));
    if (frame.payload.length === 32 && this.isZeroSignature(frame.signature!)) {
      console.log('[Received challenge] [sending response...]');
      this.pendingChallenge = frame.payload;
      const signature = this.keyManager.sign(frame.payload);
      this.connectionManager.send({
        type: MsgType.HANDSHAKE,
        payload: frame.payload,
        senderId: this.keyManager.getPublicKey(),
        signature
      });
      console.log('[Handshake response sent]');
    }
    else if (frame.payload.length === 1 && frame.payload[0] === 1 && this.isZeroSignature(frame.signature!)) {
      console.log('[Handshake confirmed by server]');
      this.handshakeCompleted = true;
      this.emit('handshakeSuccess');
    }
    else {
      console.warn('[Unexpected handshake frame]', frame);
    }
  }

  private handleData(frame: Frame): void {
    if (frame.payload.length < 32) return;
    const content = frame.payload.slice(32);
    this.emit('message', frame.senderId, content, ContentType.RAW);
  }

  private handleSignedData(frame: Frame): void {
    if (frame.payload.length < 32 + 64) return;
    const target = frame.payload.slice(0, 32);
    const signature = frame.payload.slice(32, 32 + 64);
    const fullContent = frame.payload.slice(32 + 64);

    if (!this.keyManager.verify(frame.senderId, fullContent, signature)) {
      console.warn('[Invalid content signature] [from]', Buffer.from(frame.senderId).toString('hex').slice(0,8));
      return;
    }

    let contentType = ContentType.RAW;
    let content = fullContent;
    let parsed = null;

    if (fullContent.length > 0) {
      const typeByte = fullContent[0];
      if (typeByte === ContentType.TEXT) {
        contentType = ContentType.TEXT;
        content = fullContent.slice(1);
        parsed = new TextDecoder().decode(content);
      } else if (typeByte === ContentType.JSON) {
        contentType = ContentType.JSON;
        content = fullContent.slice(1);
        try {
          parsed = JSON.parse(new TextDecoder().decode(content));
        } catch (e) {
          console.warn('[Failed to parse JSON content]');
          parsed = null;
        }
      } else if (typeByte === ContentType.FILE) {
        contentType = ContentType.FILE;
        if (fullContent.length < 2) {
          console.warn('[Malformed FILE content]: too short');
          parsed = null;
        } else {
          const nameLen = fullContent[1];
          if (nameLen === undefined) {
            console.warn('[Malformed FILE content]: nameLen undefined');
            parsed = null;
          } else if (fullContent.length < 2 + nameLen) {
            console.warn('[Malformed FILE content]: name length mismatch');
            parsed = null;
          } else {
            const nameBytes = fullContent.slice(2, 2 + nameLen);
            const fileName = new TextDecoder().decode(nameBytes);
            const fileData = fullContent.slice(2 + nameLen);
            parsed = { name: fileName, data: fileData };
            content = fileData;
          }
        }
      } else {
        contentType = ContentType.RAW;
      }
    }

    this.emit('message', frame.senderId, content, contentType, parsed);
  }

  private async handleEncryptedData(frame: Frame): Promise<void> {
    if (!this.keyManager.verify(frame.senderId, frame.payload, frame.signature!)) {
      console.warn('[Invalid signature on encrypted data] [from]', Buffer.from(frame.senderId).toString('hex').slice(0,8));
      return;
    }

    if (frame.payload.length < 32) {
      console.warn('[Encrypted data too short]');
      return;
    }
    const target = frame.payload.slice(0, 32);
    const encryptedPackage = frame.payload.slice(32);

    try {
      const decrypted = await this.keyManager.decryptFrom(frame.senderId, encryptedPackage);
      if (decrypted.length === 0) return;
      const contentType = decrypted[0] as ContentType;
      const content = decrypted.slice(1);

      let parsed = null;
      if (contentType === ContentType.TEXT) {
        parsed = new TextDecoder().decode(content);
      } else if (contentType === ContentType.JSON) {
        try {
          parsed = JSON.parse(new TextDecoder().decode(content));
        } catch (e) {
          console.warn('[Failed to parse JSON in encrypted message]');
        }
      } else if (contentType === ContentType.FILE) {
        if (content.length > 0) {
          const nameLen = content[0];
          if (nameLen === undefined) {
            console.warn('[Malformed FILE content]: nameLen undefined');
          } else if (content.length >= 1 + nameLen) {
            const name = new TextDecoder().decode(content.slice(1, 1 + nameLen));
            const data = content.slice(1 + nameLen);
            parsed = { name, data };
          } else {
            console.warn('[Malformed FILE content]: name length mismatch');
          }
        }
      }

      this.emit('message', frame.senderId, content, contentType, parsed);
    } catch (err) {
      console.warn('[Failed to decrypt message] [from]', Buffer.from(frame.senderId).toString('hex').slice(0,8), err);
    }
  }

  private handleNodeInfo(frame: Frame): void {
    const payload = frame.payload;
    if (payload.length === 0) return;
    const subType = payload[0];

    if (subType === NODE_INFO_ADD_SERVER && payload.length >= 2) {
      const addrLen = payload[1];
      if (addrLen !== undefined && payload.length >= 2 + addrLen) {
        const address = new TextDecoder().decode(payload.slice(2, 2 + addrLen));
        this.emit('nodeInfoAddServer', address);
      }
    } else if (subType === NODE_INFO_RESPONSE_SERVERS && payload.length >= 3) {
      const b1 = payload[1];
      const b2 = payload[2];
      if (b1 === undefined || b2 === undefined) return;
      const count = (b1 << 8) | b2;
      let offset = 3;
      const addresses: string[] = [];
      for (let i = 0; i < count; i++) {
        if (offset + 32 > payload.length) break;
        offset += 32;
        if (offset >= payload.length) break;
        const addrLen = payload[offset];
        if (addrLen === undefined) break;
        offset += 1;
        if (offset + addrLen > payload.length) break;
        const addrBytes = payload.slice(offset, offset + addrLen);
        const address = new TextDecoder().decode(addrBytes);
        addresses.push(address);
        offset += addrLen;
      }
      this.emit('serversListReceived', addresses);
    }
  }

  sendData(target: PublicKey, payload: Uint8Array): void {
    if (!this.handshakeCompleted) throw new Error('[Handshake not completed]');
    const fullPayload = new Uint8Array(32 + payload.length);
    fullPayload.set(target, 0);
    fullPayload.set(payload, 32);
    this.connectionManager.send({
      type: MsgType.DATA,
      payload: fullPayload,
      senderId: this.keyManager.getPublicKey()
    });
  }

  sendSigned(target: PublicKey, content: Uint8Array, contentType: ContentType = ContentType.RAW): void {
    if (!this.handshakeCompleted) throw new Error('[Handshake not completed]');
    let finalContent: Uint8Array;
    if (contentType === ContentType.RAW) {
      finalContent = content;
    } else {
      finalContent = new Uint8Array(1 + content.length);
      finalContent[0] = contentType;
      finalContent.set(content, 1);
    }

    const signature = this.keyManager.sign(finalContent);
    const fullPayload = new Uint8Array(32 + 64 + finalContent.length);
    fullPayload.set(target, 0);
    fullPayload.set(signature, 32);
    fullPayload.set(finalContent, 32 + 64);
    this.connectionManager.send({
      type: MsgType.SIGNED_DATA,
      payload: fullPayload,
      senderId: this.keyManager.getPublicKey()
    });
  }

  async sendEncrypted(target: PublicKey, content: Uint8Array, recipientEncryptionKey: Uint8Array, contentType: ContentType = ContentType.RAW): Promise<void> {
    if (!this.handshakeCompleted) throw new Error('Handshake not completed');

    const dataToEncrypt = new Uint8Array(1 + content.length);
    dataToEncrypt[0] = contentType;
    dataToEncrypt.set(content, 1);

    const encryptedPayload = await this.keyManager.encryptFor(recipientEncryptionKey, dataToEncrypt);
    const signature = this.keyManager.sign(encryptedPayload);

    const finalPayload = new Uint8Array(32 + encryptedPayload.length);
    finalPayload.set(target, 0);
    finalPayload.set(encryptedPayload, 32);

    this.connectionManager.send({
      type: MsgType.ENCRYPTED_DATA,
      payload: finalPayload,
      senderId: this.keyManager.getPublicKey(),
      signature
    });
  }

  sendNodeInfoAddServer(address: string): void {
    const encoder = new TextEncoder();
    const addrBytes = encoder.encode(address);
    const payload = new Uint8Array(2 + addrBytes.length);
    payload[0] = NODE_INFO_ADD_SERVER;
    payload[1] = addrBytes.length;
    payload.set(addrBytes, 2);
    this.connectionManager.send({
      type: MsgType.NODE_INFO,
      payload,
      senderId: this.keyManager.getPublicKey()
    });
  }

  sendRequestServers(): void {
    const payload = new Uint8Array([NODE_INFO_REQUEST_SERVERS]);
    this.connectionManager.send({
      type: MsgType.NODE_INFO,
      payload,
      senderId: this.keyManager.getPublicKey()
    });
  }
}