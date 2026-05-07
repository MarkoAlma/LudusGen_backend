// src/services/storageService.js
import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand, HeadObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

const DEFAULT_PRESIGN_TTL = 604800;

function cleanEnv(name) {
  const value = process.env[name];
  return typeof value === "string" ? value.trim() : value;
}

function inferRegion(endpoint) {
  const configuredRegion = cleanEnv("B2_REGION") || cleanEnv("AWS_REGION");
  if (configuredRegion) return configuredRegion;

  try {
    const host = new URL(endpoint).hostname;
    const match = host.match(/^s3[.-]([a-z0-9-]+)\./i);
    if (match?.[1]) return match[1];
  } catch {
    // Fall through to the historical default used by this project.
  }

  return "us-east-005";
}

function readConfig() {
  const endpoint = cleanEnv("B2_ENDPOINT");
  const accessKeyId = cleanEnv("B2_KEY_ID");
  const secretAccessKey = cleanEnv("B2_APP_KEY");
  const bucket = cleanEnv("B2_BUCKET_NAME");

  const missing = [
    ["B2_ENDPOINT", endpoint],
    ["B2_KEY_ID", accessKeyId],
    ["B2_APP_KEY", secretAccessKey],
    ["B2_BUCKET_NAME", bucket],
  ].filter(([, value]) => !value).map(([name]) => name);

  if (missing.length) {
    throw new Error(`Missing B2 storage configuration: ${missing.join(", ")}`);
  }

  const ttl = Number.parseInt(cleanEnv("B2_PRESIGN_TTL") || `${DEFAULT_PRESIGN_TTL}`, 10);

  return {
    endpoint,
    credentials: { accessKeyId, secretAccessKey },
    bucket,
    region: inferRegion(endpoint),
    ttl: Number.isFinite(ttl) ? ttl : DEFAULT_PRESIGN_TTL,
  };
}

class StorageService {
  constructor() {
    this.client = null;
    this.bucket = null;
    this.ttl = DEFAULT_PRESIGN_TTL;
  }

  getStorage() {
    if (!this.client) {
      const config = readConfig();
      this.client = new S3Client({
        region: config.region,
        endpoint: config.endpoint,
        credentials: config.credentials,
        forcePathStyle: true,
      });
      this.bucket = config.bucket;
      this.ttl = config.ttl;
    }

    return { client: this.client, bucket: this.bucket, ttl: this.ttl };
  }

  /**
   * Upload a buffer to B2.
   * @param {Buffer} buffer
   * @param {string} key
   * @param {string} contentType
   */
  async uploadFile(buffer, key, contentType) {
    try {
      const { client, bucket } = this.getStorage();
      await client.send(new PutObjectCommand({
        Bucket: bucket,
        Key: key,
        Body: buffer,
        ContentType: contentType,
      }));
      return key;
    } catch (err) {
      console.error(`[StorageService] Upload failed for ${key}:`, err.message);
      throw err;
    }
  }

  /**
   * Upload a file from disk to B2 via stream.
   * @param {string} filePath
   * @param {string} key
   * @param {string} contentType
   */
  async uploadFileFromPath(filePath, key, contentType) {
    try {
      const { client, bucket } = this.getStorage();
      const fs = await import("node:fs");
      const fileStream = fs.createReadStream(filePath);
      
      await client.send(new PutObjectCommand({
        Bucket: bucket,
        Key: key,
        Body: fileStream,
        ContentType: contentType,
      }));
      return key;
    } catch (err) {
      console.error(`[StorageService] Stream upload failed for ${key}:`, err.message);
      throw err;
    }
  }

  /**
   * Check if an object exists in B2.
   * @param {string} key
   */
  async exists(key) {
    try {
      const { client, bucket } = this.getStorage();
      await client.send(new HeadObjectCommand({
        Bucket: bucket,
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
      const { client, bucket, ttl } = this.getStorage();
      const command = new GetObjectCommand({
        Bucket: bucket,
        Key: key,
      });
      return await getSignedUrl(client, command, { expiresIn: expiresIn || ttl });
    } catch (err) {
      console.error(`[StorageService] Signed URL failed for ${key}:`, err.message);
      return null;
    }
  }

  /**
   * Generate a signed download URL with attachment headers.
   * @param {string} key
   * @param {string} filename
   * @param {number} [expiresIn]
   */
  async getSignedDownloadUrl(key, filename, expiresIn) {
    try {
      const { client, bucket, ttl } = this.getStorage();
      const command = new GetObjectCommand({
        Bucket: bucket,
        Key: key,
        ResponseContentDisposition: `attachment; filename="${String(filename || key.split("/").pop()).replace(/"/g, "")}"`,
      });
      return await getSignedUrl(client, command, { expiresIn: expiresIn || ttl });
    } catch (err) {
      console.error(`[StorageService] Download URL failed for ${key}:`, err.message);
      return null;
    }
  }

  /**
   * Read a B2 object into memory.
   * @param {string} key
   * @returns {Promise<Buffer>}
   */
  async getFileBuffer(key) {
    try {
      const { client, bucket } = this.getStorage();
      const data = await client.send(new GetObjectCommand({
        Bucket: bucket,
        Key: key,
      }));

      if (data.Body?.transformToByteArray) {
        return Buffer.from(await data.Body.transformToByteArray());
      }

      const chunks = [];
      for await (const chunk of data.Body) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      }
      return Buffer.concat(chunks);
    } catch (err) {
      console.error(`[StorageService] Read failed for ${key}:`, err.message);
      throw err;
    }
  }

  /**
   * Read a B2 object as a stream with its metadata.
   * @param {string} key
   */
  async getFileObject(key) {
    try {
      const { client, bucket } = this.getStorage();
      return await client.send(new GetObjectCommand({
        Bucket: bucket,
        Key: key,
      }));
    } catch (err) {
      console.error(`[StorageService] Stream read failed for ${key}:`, err.message);
      throw err;
    }
  }

  /**
   * Delete an object from B2.
   * @param {string} key
   */
  async deleteFile(key) {
    try {
      const { client, bucket } = this.getStorage();
      await client.send(new DeleteObjectCommand({
        Bucket: bucket,
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
