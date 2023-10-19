import { createLogger } from '../../utils/logger.mjs';
import { TodosAccess } from '../dataLayer/todos.mjs';
import { uuid } from 'uuidv4';
import { AttachmentS3 } from '../utils/s3Attachment.mjs';

const logger = createLogger('businessLogic');

const todosAccess = new TodosAccess();
const attachmentS3 = new AttachmentS3();

//gets item for user
export async function getTodos(userId) {
    logger.info('---getTodos event Business---');

    return todosAccess.getAllTodos(userId)
}

//create item  
export async function createTodo(newTodo, userId) {
    logger.info('---CreateTodo event Business---');

    const todoId = uuid();
    const createdAt = new Date().toISOString();
    const attachmentUrl = attachmentS3.buildAttachmentUrl(todoId);
    const newItem = {
        userId,
        todoId,
        createdAt,
        done: false,
        attachmentUrl: attachmentUrl,
        ...newTodo
    };

    return await todosAccess.createTodo(newItem);
}

//update item
export async function updateTodo(userId, todoId, todoUpdate) {
    logger.info('---updateTodo event Business---');

    return await todosAccess.updateTodoItem(userId, todoId, todoUpdate);
}

//delete item 
export async function deleteTodo(todoId, userId) {
    logger.info('---deleteTodo event Business---');

    return await todosAccess.deleteTodoItem(todoId, userId);
}

//generate upload url 
export async function createAttachmentPresignedUrl(todoId, userId) {
    logger.info('---createAttachmentPresignedUrl event Business---');

    return await attachmentS3.getUploadUrl(todoId);
}