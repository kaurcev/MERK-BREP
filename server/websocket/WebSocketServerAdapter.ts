import WebSocket, { WebSocketServer } from 'ws';
import { IConnectionManager, IConnectionListener, ILogger } from '../core/types';
import { WebSocketConnection } from './WebSocketConnection';
import { MessageDispatcher } from '../messaging/MessageDispatcher';
import { decodeFrame } from '../../shared/protocol';

export class WebSocketServerAdapter implements IConnectionManager {
  private wss: WebSocketServer;
  private listeners: IConnectionListener[] = [];

  constructor(
    port: number,
    private dispatcher: MessageDispatcher,
    private logger: ILogger
  ) {
    this.wss = new WebSocketServer({ port });
    this.wss.on('connection', (ws: WebSocket) => {
      const connection = new WebSocketConnection(ws);
      this.logger.info(`New connection: ${connection.id}`);
      this.listeners.forEach(listener => listener.onConnection(connection));

      ws.on('message', async (data: WebSocket.RawData) => {
        try {
          let arrayBuffer: ArrayBuffer;
          if (Buffer.isBuffer(data)) {
            arrayBuffer = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
          } else if (data instanceof ArrayBuffer) {
            arrayBuffer = data;
          } else if (Array.isArray(data)) {
            const totalLength = data.reduce((acc, buf) => acc + buf.length, 0);
            const combined = Buffer.concat(data);
            arrayBuffer = combined.buffer.slice(combined.byteOffset, combined.byteOffset + combined.byteLength) as ArrayBuffer;
          } else {
            this.logger.error(`Unexpected message type from ${connection.id}: ${typeof data}`);
            return;
          }
          const frame = decodeFrame(arrayBuffer);
          await this.dispatcher.dispatch(connection, frame);
        } catch (err) {
          this.logger.error(`Error handling message from ${connection.id}:`, err);
          connection.close();
        }
      });

      ws.on('close', () => {
        this.logger.info(`Connection closed: ${connection.id}`);
      });
    });
  }

  start(): void {
    this.logger.info(`WebSocket server started on port ${(this.wss.options as any).port}`);
  }

  stop(): void {
    this.wss.close();
  }

  registerListener(listener: IConnectionListener): void {
    this.listeners.push(listener);
  }

  unregisterListener(listener: IConnectionListener): void {
    const index = this.listeners.indexOf(listener);
    if (index !== -1) this.listeners.splice(index, 1);
  }
}