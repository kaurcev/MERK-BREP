import { MsgType } from '../../shared/protocol';

export type HexString = string;
export type PublicKey = Uint8Array;
export type PrivateKey = Uint8Array;
export type Signature = Uint8Array;
export type EncryptionPublicKey = Uint8Array;
export type EncryptionPrivateKey = Uint8Array;

export enum ContentType {
  RAW = 0,
  TEXT = 1,
  JSON = 2,
  FILE = 3,
}

export interface Frame {
  type: MsgType;
  payload: Uint8Array;
  senderId: PublicKey;
  signature?: Signature;
}

export interface MessageEvent {
  from: PublicKey;
  content: Uint8Array;
  contentType?: ContentType;
  parsed?: any;
}