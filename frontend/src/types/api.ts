export interface DirectoryUser {
  username: string;
  identityPublicKeyECDH: string;
  identityPublicKeyECDSA: string;
}

export interface InboxFile {
  filepath: string;
  originalFilename: string;
  fileSize: number;
  fileIv: string;
  wrappedFileKey: string;
  ephemeralPublicKey: string;
  usedPreKey: string;
  senderUsername: string;
  signature: string;
  encryptedPrivatePreKey: string;
  preKeyIv: string;
  timestamp: number;
}
