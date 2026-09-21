import crypto from 'node:crypto';
import { PrismaClient } from '@prisma/client';

export const prisma = new PrismaClient();
const key = Buffer.from(process.env.SOURCE_ENCRYPTION_KEY || '', 'base64');

function encryptionKey() {
  if (key.length !== 32) throw new Error('SOURCE_ENCRYPTION_KEY must decode to 32 bytes');
  return key;
}

export function encryptSource(source: string) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(source, 'utf8'), cipher.final()]);
  return { encryptedSource: `${encrypted.toString('base64')}.${cipher.getAuthTag().toString('base64')}`, sourceIv: iv.toString('base64') };
}

export function decryptSource(encryptedSource: string, sourceIv: string) {
  const [body, tag] = encryptedSource.split('.');
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey(), Buffer.from(sourceIv, 'base64'));
  decipher.setAuthTag(Buffer.from(tag, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(body, 'base64')), decipher.final()]).toString('utf8');
}

export const hashIp = (ip: string) => crypto.createHmac('sha256', process.env.JWT_SECRET || 'dev-secret').update(ip).digest('hex');
export const newToken = () => crypto.randomBytes(24).toString('base64url');
