import fs from "fs";
import path from "path";
import { Client as MinioClient } from "minio";
import type { Response } from "express";

export type BlobStorageDriver = "local" | "s3";

export interface BlobStorageConfig {
  driver: BlobStorageDriver;
  localDir: string;
  bucket: string;
  endpoint: string;
  port: number;
  useSSL: boolean;
  accessKey: string;
  secretKey: string;
  region?: string;
}

const SAFE_OBJECT_KEY_PATTERN = /^[a-zA-Z0-9._-]{1,200}$/;

function assertSafeObjectKey(key: string) {
  if (!SAFE_OBJECT_KEY_PATTERN.test(key) || key === "." || key === "..") {
    throw new Error("Unsafe encrypted blob storage key.");
  }
}

function safeDownloadName(name?: string) {
  const fallback = "encrypted-blob.bin";
  if (!name) return fallback;
  const basename = path.basename(name).replace(/[\r\n"]/g, "_").trim();
  return basename && basename !== "." && basename !== ".." ? basename.slice(0, 180) : fallback;
}

function contentDispositionAttachment(name?: string) {
  const safeName = safeDownloadName(name);
  return `attachment; filename="${safeName.replace(/\\/g, "\\\\")}"; filename*=UTF-8''${encodeURIComponent(safeName)}`;
}

function parseS3Endpoint(rawEndpoint: string) {
  const withProtocol = rawEndpoint.includes("://") ? rawEndpoint : `http://${rawEndpoint}`;
  const parsed = new URL(withProtocol);
  return {
    endpoint: parsed.hostname,
    port: parsed.port ? Number(parsed.port) : parsed.protocol === "https:" ? 443 : 80,
    useSSL: parsed.protocol === "https:"
  };
}

export function loadBlobStorageConfig(localDir: string): BlobStorageConfig {
  const driver = (process.env.STORAGE_DRIVER || "local").toLowerCase() === "s3" ? "s3" : "local";
  const endpoint = parseS3Endpoint(process.env.S3_ENDPOINT || "http://127.0.0.1:9000");

  return {
    driver,
    localDir,
    bucket: process.env.S3_BUCKET || "crypshare-vault",
    endpoint: endpoint.endpoint,
    port: Number(process.env.S3_PORT || endpoint.port),
    useSSL: process.env.S3_USE_SSL ? process.env.S3_USE_SSL === "true" : endpoint.useSSL,
    accessKey: process.env.S3_ACCESS_KEY || "crypshare",
    secretKey: process.env.S3_SECRET_KEY || "change-this-minio-password",
    region: process.env.S3_REGION || undefined
  };
}

export class BlobStorage {
  private minio: MinioClient | null = null;
  private ready: Promise<void> | null = null;

  constructor(private readonly config: BlobStorageConfig) {
    fs.mkdirSync(config.localDir, { recursive: true });

    if (config.driver === "s3") {
      this.minio = new MinioClient({
        endPoint: config.endpoint,
        port: config.port,
        useSSL: config.useSSL,
        accessKey: config.accessKey,
        secretKey: config.secretKey,
        region: config.region
      });
    }
  }

  get driver() {
    return this.config.driver;
  }

  async ensureReady() {
    if (this.ready) return this.ready;

    this.ready = (async () => {
      if (!this.minio) return;
      const exists = await this.minio.bucketExists(this.config.bucket);
      if (!exists) {
        await this.minio.makeBucket(this.config.bucket, this.config.region || "");
      }
    })();

    return this.ready;
  }

  localPath(key: string) {
    assertSafeObjectKey(key);
    const resolved = path.resolve(this.config.localDir, key);
    const root = path.resolve(this.config.localDir);
    if (resolved !== root && !resolved.startsWith(`${root}${path.sep}`)) {
      throw new Error("Encrypted blob storage key escapes storage root.");
    }
    return resolved;
  }

  async putFile(key: string, sourcePath: string) {
    await this.ensureReady();
    assertSafeObjectKey(key);

    if (!this.minio) {
      const targetPath = this.localPath(key);
      if (path.resolve(sourcePath) === path.resolve(targetPath)) return;
      fs.mkdirSync(path.dirname(targetPath), { recursive: true });
      fs.copyFileSync(sourcePath, targetPath);
      return;
    }

    await this.minio.fPutObject(this.config.bucket, key, sourcePath);
  }

  async exists(key: string) {
    await this.ensureReady();
    assertSafeObjectKey(key);

    if (!this.minio) {
      return fs.existsSync(this.localPath(key));
    }

    try {
      await this.minio.statObject(this.config.bucket, key);
      return true;
    } catch {
      return false;
    }
  }

  async delete(key: string) {
    await this.ensureReady();
    assertSafeObjectKey(key);

    if (!this.minio) {
      fs.rmSync(this.localPath(key), { force: true });
      return;
    }

    try {
      await this.minio.removeObject(this.config.bucket, key);
    } catch {
      // Deleting a missing encrypted object should remain idempotent.
    }
  }

  async sendDownload(key: string, res: Response, downloadName?: string) {
    await this.ensureReady();
    assertSafeObjectKey(key);

    if (!this.minio) {
      res.download(this.localPath(key), safeDownloadName(downloadName));
      return;
    }

    const objectStream = await this.minio.getObject(this.config.bucket, key);
    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader("Content-Disposition", contentDispositionAttachment(downloadName || key));
    objectStream.on("error", () => {
      if (!res.headersSent) {
        res.status(500).json({ error: "Unable to stream encrypted blob" });
      } else {
        res.destroy();
      }
    });
    objectStream.pipe(res);
  }
}
