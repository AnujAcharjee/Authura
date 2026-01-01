import Redis, { RedisOptions } from 'ioredis';
import { ENV } from '@/config/env';

const options: RedisOptions = {
  host: ENV.REDIS_HOST,
  username: ENV.REDIS_USERNAME,
  port: ENV.REDIS_PORT,
  password: ENV.REDIS_PASSWORD,
  db: 0,
  maxRetriesPerRequest: null,
};

const redis = new Redis(options);

let isShuttingDown = false;
const handleShutdown = async () => {
  if (isShuttingDown) return;
  isShuttingDown = true;

  console.log('Shutting down Redis connection');
  await redis.quit();
};

process.on('SIGTERM', handleShutdown);
process.on('SIGINT', handleShutdown);

export default redis;
