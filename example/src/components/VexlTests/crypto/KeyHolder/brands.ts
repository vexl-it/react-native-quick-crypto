export type PrivateKeyPemBase64 = string;

export type PublicKeyPemBase64 = string;

export type PrivateKeyHolder = {
  publicKeyPemBase64: string;
  privateKeyPemBase64: string;
};
