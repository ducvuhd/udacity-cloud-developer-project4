import middy from '@middy/core';
import cors from '@middy/http-cors';
import httpErrorHandler from '@middy/http-error-handler';
import { getUserId } from '../utils.mjs';
import { getTodos } from '../../businessLogic/todos.mjs';
import { createLogger } from '../../utils/logger.mjs';

const logger = createLogger('http layer');

export const handler = middy()
  .use(httpErrorHandler())
  .use(
    cors({
      credentials: true
    })
  )
  .handler(async (event) => {
    logger.info('---getTodos event http---');
    const userId = getUserId(event);
    const todos = await getTodos(userId);

    return {
      statusCode: 200,
      body: JSON.stringify({
        items: todos
      })
    };
  });