import AWS from 'aws-sdk';
import AWSXRay from 'aws-xray-sdk';

const s3Bucket = process.env.IMAGES_S3_BUCKET;
const urlExpiration = process.env.SIGNED_URL_EXPIRATION;

export class AttachmentS3 {

    buildAttachmentUrl(todoId) {
        return `https://${s3Bucket}.s3.amazonaws.com/${todoId}`;
    }

    getUploadUrl(todoId) {
        const XAWS = AWSXRay.captureAWS(AWS);
        const s3 = new XAWS.S3({ signatureVersion: 'v4' });

        return s3.getSignedUrl('putObject', {
            Bucket: s3Bucket,
            Key: todoId,
            Expires: urlExpiration
        });
    }
}