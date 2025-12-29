import app from './app';
import { ENV } from '@/config/env';
import { logger } from '@/config/logger';

const server = app.listen(ENV.PORT, () => {
  logger.info(`Server running on port ${ENV.PORT} in ${ENV.NODE_ENV} mode`);
});

// Graceful shutdown

let isShuttingDown = false;

const shutdown = async (signal: string) => {
  if (isShuttingDown) return;
  isShuttingDown = true;

  logger.info('Shutdown signal received');

  // Add connection draining
  app.disable('connection'); // Stop accepting new connections

  server.close(async () => {
    logger.info('HTTP server closed');
    
    //

    process.exit(0);
  });

  // Force shutdown after 30 seconds
  setTimeout(() => {
    logger.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 30000);
};

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

export default server;
