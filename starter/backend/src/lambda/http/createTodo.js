import 'source-map-support/register';
import middy from '@middy/core';
import cors from '@middy/http-cors';
import httpErrorHandler from '@middy/http-error-handler';
import { createTodo } from '../../businessLogic/todos.mjs';
import { getUserId } from '../utils.mjs';
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
    logger.info('---CreateTodo event http---');
    const newTodo = JSON.parse(event.body)

    // TODO: Implement creating a new TODO item
    // Write your logic here
    const userId = getUserId(event);
    const newIitem = await createTodo(newTodo, userId);

    return {
      statusCode: 201,
      body: JSON.stringify({ item: newIitem })
    };
  });
