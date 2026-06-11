import { apiUrl } from '../config/api';

export const DEFAULT_UPLOAD_FILE_LIMIT_BYTES = 15 * 1024 * 1024 * 1024;

export interface UploadLimits {
  uploadFileLimitBytes: number;
  uploadFieldLimitBytes: number;
  mode: string;
  note: string;
}

export function formatBytes(bytes: number) {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = Math.max(bytes, 0);
  let unitIndex = 0;

  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }

  const digits = unitIndex <= 1 ? 0 : value >= 100 ? 0 : value >= 10 ? 1 : 2;
  return `${value.toFixed(digits)} ${units[unitIndex]}`;
}

export async function fetchUploadLimits(): Promise<UploadLimits> {
  const res = await fetch(apiUrl('/upload-limits'));
  const data = await res.json() as Partial<UploadLimits> & { error?: string };
  if (!res.ok) throw new Error(data.error || 'Unable to load upload limits.');

  return {
    uploadFileLimitBytes: Number(data.uploadFileLimitBytes || DEFAULT_UPLOAD_FILE_LIMIT_BYTES),
    uploadFieldLimitBytes: Number(data.uploadFieldLimitBytes || 262144),
    mode: data.mode || 'single-request',
    note: data.note || 'Current public-beta uploads are single encrypted multipart requests.'
  };
}
