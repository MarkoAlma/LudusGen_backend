// src/services/storageService.js
import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand, HeadObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

class StorageService {
  constructor() {
    this.client = new S3Client({
      region: "us-east-005", // B2 often works with this or specific regions
      endpoint: process.env.B2_ENDPOINT,
      credentials: {
        accessKeyId: process.env.B2_KEY_ID,
        secretAccessKey: process.env.B2_APP_KEY,
      },
      forcePathStyle: true,
    });
    this.bucket = process.env.B2_BUCKET_NAME;
    this.ttl = parseInt(process.env.B2_PRESIGN_TTL || "604800", 10);
  }

  /**
   * Upload a buffer to B2.
   * @param {Buffer} buffer
   * @param {string} key
   * @param {string} contentType
   */
  async uploadFile(buffer, key, contentType) {
    try {
      await this.client.send(new PutObjectCommand({
        Bucket: this.bucket,
        Key: key,
        Body: buffer,
        ContentType: contentType,
      }));
      console.log(`[StorageService] Uploaded ${key} (${buffer.length} bytes)`);
      return key;
    } catch (err) {
      console.error(`[StorageService] Upload failed for ${key}:`, err.message);
      throw err;
    }
  }

  /**
   * Check if an object exists in B2.
   * @param {string} key
   */
  async exists(key) {
    try {
      await this.client.send(new HeadObjectCommand({
        Bucket: this.bucket,
        Key: key,
      }));
      return true;
    } catch (err) {
      if (err.name === "NotFound" || err.$metadata?.httpStatusCode === 404) return false;
      throw err;
    }
  }

  /**
   * Generate a signed URL for a B2 object.
   * @param {string} key
   * @param {number} [expiresIn]
   */
  async getSignedUrl(key, expiresIn) {
    try {
      const command = new GetObjectCommand({
        Bucket: this.bucket,
        Key: key,
      });
      return await getSignedUrl(this.client, command, { expiresIn: expiresIn || this.ttl });
    } catch (err) {
      console.error(`[StorageService] Signed URL failed for ${key}:`, err.message);
      return null;
    }
  }

  /**
   * Delete an object from B2.
   * @param {string} key
   */
  async deleteFile(key) {
    try {
      await this.client.send(new DeleteObjectCommand({
        Bucket: this.bucket,
        Key: key,
      }));
      return true;
    } catch (err) {
      console.warn(`[StorageService] Delete failed for ${key}:`, err.message);
      return false;
    }
  }
}

export const storageService = new StorageService();
