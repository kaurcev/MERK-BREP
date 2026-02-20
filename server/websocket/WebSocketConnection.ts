import WebSocket from 'ws';
import { IConnection } from '../core/types';
import { Frame, encodeFrame } from '../../shared/protocol';
import { logger } from '../logger';

export class WebSocketConnection implements IConnection {
  public readonly id: string;
  public peerType?: 'client' | 'server';

  constructor(private ws: WebSocket) {
    this.id = Math.random().toString(36).substring(2, 10);
  }

  send(frame: Frame): void {
    if (this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(encodeFrame(frame));
    } else {
      logger.warn(`Attempt to send on closed connection ${this.id}`);
    }
  }

  close(): void {
    this.ws.close();
  }

  get isOpen(): boolean {
    return this.ws.readyState === WebSocket.OPEN;
  }
}