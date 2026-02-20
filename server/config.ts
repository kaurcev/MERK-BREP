export interface Config {
  port: number;
  seedPeers: string[];
}

const port = process.env.PORT ? parseInt(process.env.PORT, 10) : 8080;
const seedPeers: string[] = [];

const args = process.argv.slice(2);
const connectIndex = args.indexOf('--connect');
if (connectIndex !== -1) {
  const peerAddress = args[connectIndex + 1];
  if (peerAddress) {
    seedPeers.push(peerAddress);
  }
}

export const config: Config = {
  port,
  seedPeers,
};