import { RelayServer } from './RelayServer';
import { config } from './config';
import { logger } from './logger';

const server = new RelayServer(config, logger);
server.start().catch(err => {
  logger.error('Failed to start server:', err);
  process.exit(1);
});