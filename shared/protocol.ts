export const MAGIC = 0x58;
export const VERSION = 0x01;
export enum MsgType {
  HANDSHAKE = 1,
  DATA = 2,
  NODE_INFO = 3,
  SIGNED_DATA = 4,
  ENCRYPTED_DATA = 5
}

export const NODE_INFO_REQUEST_CLIENTS = 0;
export const NODE_INFO_RESPONSE_CLIENTS = 1;
export const NODE_INFO_REQUEST_SERVERS = 2;
export const NODE_INFO_RESPONSE_SERVERS = 3;
export const NODE_INFO_ADD_SERVER = 4;
export const NODE_INFO_QUERY_CLIENT = 5;
export const NODE_INFO_QUERY_RESPONSE = 6;

export interface Frame {
  type: MsgType;
  payload: Uint8Array;
  senderId: Uint8Array;
  signature?: Uint8Array;
}

export function encodeFrame(frame: Frame): ArrayBuffer {
  const header = new ArrayBuffer(120);
  const dv = new DataView(header);
  dv.setUint8(0, MAGIC);
  dv.setUint8(1, VERSION);
  dv.setUint8(2, frame.type);
  dv.setUint8(3, 0);
  dv.setUint32(4, frame.payload.length, false);
  for (let i = 0; i < 16; i++) dv.setUint8(8 + i, 0);
  new Uint8Array(header, 24, 32).set(frame.senderId);
  const signature = frame.signature || new Uint8Array(64);
  new Uint8Array(header, 56, 64).set(signature);

  const total = new Uint8Array(120 + frame.payload.length);
  total.set(new Uint8Array(header), 0);
  total.set(frame.payload, 120);
  return total.buffer;
}

export function decodeFrame(buffer: ArrayBuffer): Frame {
  if (buffer.byteLength < 120) throw new Error('frame too short');
  const dv = new DataView(buffer);
  if (dv.getUint8(0) !== MAGIC) throw new Error('bad magic');
  const type = dv.getUint8(2) as MsgType;
  const len = dv.getUint32(4, false);
  if (buffer.byteLength < 120 + len) throw new Error('incomplete frame');
  const senderId = new Uint8Array(buffer, 24, 32);
  const signature = new Uint8Array(buffer, 56, 64);
  const payload = new Uint8Array(buffer, 120, len);
  return { type, payload, senderId, signature };
}

export type PublicKey = Uint8Array;