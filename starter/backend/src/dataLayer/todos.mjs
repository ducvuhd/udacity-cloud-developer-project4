import { createLogger } from '../utils/logger.mjs';
import AWS from 'aws-sdk';
import AWSXRay from 'aws-xray-sdk';

const logger = createLogger('dataAccessLayer');

const XAWS = AWSXRay.captureAWS(AWS);
const docClient = new XAWS.DynamoDB.DocumentClient();
const todosTable = process.env.TODOS_TABLE;
const todosIndex = process.env.INDEX_NAME;

export class TodosAccess {

    async getTodos(userId) {
        logger.info('getTodos function');

        const result = await docClient
            .query({
                TableName: todosTable,
                IndexName: todosIndex,
                KeyConditionExpression: 'userId = :userId',
                ExpressionAttributeValues: {
                    ':userId': userId
                }
            })
            .promise();

        return result.Items;
    }

    async createTodo(newItem) {
        logger.info('createTodo function');

        const result = await docClient.put({
            TableName: todosTable,
            Item: newItem
        }).promise();

        logger.info(`Create toto item: ${result}`);

        return newItem;
    }

    async updateTodo(userId, todoId, updateItem) {
        logger.info('updateTodo function');
    
        await docClient
          .update({
            TableName: todosTable,
            Key: {
              todoId,
              userId
            },
            UpdateExpression: 'set #name = :name, dueDate = :dueDate, done = :done',
            ExpressionAttributeValues: {
              ':name': updateItem.name,
              ':dueDate': updateItem.dueDate,
              ':done': updateItem.done
            },
            ExpressionAttributeNames: {
              '#name': 'name'
            },
            ReturnValues: 'UPDATED_NEW'
          })
          .promise();
    
        return updateItem;
      }
    
      async deleteTodo(todoId, userId) {
        logger.info('deleteTodo function');
    
        const result = await docClient
          .delete({
            TableName: todosTable,
            Key: {
              todoId,
              userId
            }
          })
          .promise();
    
        logger.info('Todo item deleted', result);
    
        return result;
      }
    
      async updateTodoAttachmentUrl(todoId, userId, attachmentUrl) {
        logger.info('updateTodoAttachmentUrl function');
    
        await docClient
          .update({
            TableName: todosTable,
            Key: {
              todoId,
              userId
            },
            UpdateExpression: 'set attachmentUrl = :attachmentUrl',
            ExpressionAttributeValues: {
              ':attachmentUrl': attachmentUrl
            }
          })
          .promise();
      }
}