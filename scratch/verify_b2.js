
import dotenv from 'dotenv';
import { S3Client, HeadObjectCommand } from '@aws-sdk/client-s3';
dotenv.config();

const b2 = new S3Client({
    region: 'us-east-005',
    endpoint: process.env.B2_ENDPOINT,
    credentials: { accessKeyId: process.env.B2_KEY_ID, secretAccessKey: process.env.B2_APP_KEY },
    forcePathStyle: true,
});

async function checkExists(key) {
    try {
        await b2.send(new HeadObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: key }));
        return true;
    } catch (err) {
        if (err.name === 'NotFound') {
            return false;
        }
        console.error(`⚠️ Error checking ${key}:`, err.message);
        return null;
    }
}

const keyToCheck = process.argv[2];
if (keyToCheck) {
    checkExists(keyToCheck);
} else {
}
