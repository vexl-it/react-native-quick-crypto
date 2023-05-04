import crypto from 'node:crypto';
import { PBKDF2ITER, SALT } from '../constants';
import { removeEmptyBytesAtTheEnd } from '../utils';

/**
 * Will encrypt data as GCM would but will not generate TAG. Uses CTR with special tag, to simulate GCM encryption.
 * @param data
 * @param password
 */
export function aesGCMIgnoreTagEncrypt({
  data,
  password,
}: {
  data: string;
  password: string;
}): string {
  const stretchedPass = crypto.pbkdf2Sync(
    password,
    SALT,
    PBKDF2ITER,
    32 + 12,
    'sha1'
  );

  const cipherKey = stretchedPass.subarray(0, 32);
  const iv = Buffer.concat([
    stretchedPass.subarray(32, 32 + 12),
    Buffer.from([0, 0, 0, 2]),
  ]);

  const cipher = crypto.createCipheriv('aes-256-ctr', cipherKey, iv);
  cipher.setAutoPadding(false);

  const encrypted = Buffer.concat([
    cipher.update(data, 'utf8'),
    cipher.final(),
  ]);

  return encrypted.toString('base64');
}

/**
 * Will decrypt data as GCM would but will not generate TAG. Uses CTR with special tag, to simulate GCM decryption.
 * @param data
 * @param password
 */
export function aesGCMIgnoreTagDecrypt({
  data,
  password,
}: {
  data: string;
  password: string;
}): string {
  const stretchedPass = crypto.pbkdf2Sync(
    password,
    SALT,
    PBKDF2ITER,
    108,
    'sha1'
  );

  const decipher = crypto.createDecipheriv(
    'aes-256-ctr',
    stretchedPass.subarray(0, 32),
    Buffer.concat([
      stretchedPass.subarray(32, 32 + 12),
      Buffer.from([0, 0, 0, 2]),
    ])
  );

  return removeEmptyBytesAtTheEnd(
    Buffer.concat([decipher.update(data, 'base64'), decipher.final()])
  ).toString('utf8');
}
