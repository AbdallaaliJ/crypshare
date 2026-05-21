/**
 * Generates a cryptographically secure 16-byte random salt.
 */
export function generateSalt(): Uint8Array {
  return window.crypto.getRandomValues(new Uint8Array(16));
}

/**
 * Derives a Key Encryption Key (KEK) using PBKDF2 with SHA-256 and 100,000 iterations.
 * @param password The user's plaintext password.
 * @param salt The unique salt.
 * @returns A promise resolving to the derived AES-GCM 256-bit CryptoKey.
 */
export async function deriveKEK(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const enc = new TextEncoder();
  
  // 1. Import the password into a format Web Crypto can use
  const keyMaterial = await window.crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits", "deriveKey"]
  );

  // 2. Derive the actual AES-GCM encryption key
  return window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt as any,
      iterations: 100000,
      hash: "SHA-256"
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    true, // extractable
    ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
  );
}

/**
 * Utility to convert Uint8Array to hex format (useful for logging/storing salts)
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Generates an ECDH Keypair on the P-256 curve.
 */
export async function generateIdentityKeyPair(): Promise<CryptoKeyPair> {
  return window.crypto.subtle.generateKey(
    {
      name: "ECDH",
      namedCurve: "P-256",
    },
    true, // Extractable so we can wrap/export it
    ["deriveKey", "deriveBits"]
  );
}

/**
 * Wraps the private key securely using the provided AES-GCM Key Encryption Key.
 */
export async function wrapPrivateKey(kek: CryptoKey, privateKey: CryptoKey): Promise<{ ciphertext: string, iv: string }> {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  
  const wrapped = await window.crypto.subtle.wrapKey(
    "pkcs8",
    privateKey,
    kek,
    { name: "AES-GCM", iv }
  );

  return {
    ciphertext: bytesToHex(new Uint8Array(wrapped)),
    iv: bytesToHex(iv) // Store this safely alongside ciphertext!
  };
}

/**
 * Exports the public key into a usable hex format.
 */
export async function exportPublicKey(publicKey: CryptoKey): Promise<string> {
  const exported = await window.crypto.subtle.exportKey("spki", publicKey);
  return bytesToHex(new Uint8Array(exported));
}

export async function generateSigningKeyPair(): Promise<CryptoKeyPair> {
  return window.crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
}

export async function signPayload(privateKey: CryptoKey, payload: string): Promise<string> {
  const enc = new TextEncoder();
  const signature = await window.crypto.subtle.sign(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    privateKey,
    enc.encode(payload)
  );
  return bytesToHex(new Uint8Array(signature));
}

export async function verifySignature(publicKey: CryptoKey, signatureHex: string, payload: string): Promise<boolean> {
  const enc = new TextEncoder();
  const signatureBytes = hexToBytes(signatureHex);
  return window.crypto.subtle.verify(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    publicKey,
    signatureBytes as any,
    enc.encode(payload)
  );
}

export async function importECDSAPublicKey(hexKey: string): Promise<CryptoKey> {
  const keyBytes = hexToBytes(hexKey);
  return window.crypto.subtle.importKey(
    "spki",
    keyBytes as any,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"]
  );
}

export async function deriveRawSecret(privateKey: CryptoKey, publicKey: CryptoKey): Promise<Uint8Array> {
  const bits = await window.crypto.subtle.deriveBits(
    { name: "ECDH", public: publicKey },
    privateKey,
    256
  );
  return new Uint8Array(bits);
}

export async function unwrapPrivateKey(
  encryptedPrivateKeyHex: string,
  ivHex: string,
  kek: CryptoKey,
  type: "ECDH" | "ECDSA" = "ECDH"
): Promise<CryptoKey> {
  return window.crypto.subtle.unwrapKey(
    "pkcs8",
    hexToBytes(encryptedPrivateKeyHex) as any,
    kek,
    { name: "AES-GCM", iv: hexToBytes(ivHex) as any },
    { name: type, namedCurve: "P-256" },
    false,
    type === "ECDH" ? ["deriveBits"] : ["sign"]
  );
}

// ==========================================
// Phase 2: Hybrid Encryption (Secure Data)
// ==========================================

export async function generateFileKey(): Promise<CryptoKey> {
  return window.crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true, // Extractable so it can be wrapped
    ["encrypt", "decrypt"]
  );
}

export async function encryptFileData(fileKey: CryptoKey, dataText: string): Promise<{ ciphertext: string, iv: string }> {
  const enc = new TextEncoder();
  const dataBytes = enc.encode(dataText);
  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  const encryptedBuf = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    fileKey,
    dataBytes
  );

  return {
    ciphertext: bytesToHex(new Uint8Array(encryptedBuf)),
    iv: bytesToHex(iv)
  };
}

export async function importPublicKey(hexKey: string): Promise<CryptoKey> {
  const keyBytes = new Uint8Array(hexKey.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));
  return window.crypto.subtle.importKey(
    "spki",
    keyBytes,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );
}

export async function generatePreKeys(kek: CryptoKey, count: number): Promise<{ publicKeyHex: string, encryptedPrivateKey: string, iv: string }[]> {
  const preKeys = [];
  for (let i = 0; i < count; i++) {
    const keyPair = await generateIdentityKeyPair();
    const publicKeyHex = await exportPublicKey(keyPair.publicKey);
    const { ciphertext, iv } = await wrapPrivateKey(kek, keyPair.privateKey);
    preKeys.push({
      publicKeyHex,
      encryptedPrivateKey: ciphertext,
      iv
    });
  }
  return preKeys;
}

export async function encryptFileKeyWithX3DH(
  fileKey: CryptoKey,
  recipientPreKeyHex: string,
  recipientIdentityKeyHex: string,
  senderIdentityPrivateKey: CryptoKey
): Promise<{ wrappedFileKey: string, ephemeralPublicKey: string }> {
  // Convert the hex keys into usable CryptoKeys
  const recipientPreKey = await importPublicKey(recipientPreKeyHex);
  const recipientIdentityKey = await importPublicKey(recipientIdentityKeyHex);
  
  // Alice generates her Ephemeral KeyPair
  const ephemeralPair = await generateIdentityKeyPair();

  // X3DH Math
  const dh1 = await deriveRawSecret(senderIdentityPrivateKey, recipientPreKey);
  const dh2 = await deriveRawSecret(ephemeralPair.privateKey, recipientIdentityKey);
  const dh3 = await deriveRawSecret(ephemeralPair.privateKey, recipientPreKey);

  const combined = new Uint8Array(dh1.length + dh2.length + dh3.length);
  combined.set(dh1, 0);
  combined.set(dh2, dh1.length);
  combined.set(dh3, dh1.length + dh2.length);

  // SHA-256 KDF to generate Shared KEK
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', combined);
  const sharedKek = await window.crypto.subtle.importKey(
    "raw",
    hashBuffer,
    { name: "AES-GCM" },
    false,
    ["wrapKey"]
  );

  const wrapIv = window.crypto.getRandomValues(new Uint8Array(12));
  const wrappedKeyBuf = await window.crypto.subtle.wrapKey(
    "raw",
    fileKey,
    sharedKek,
    { name: "AES-GCM", iv: wrapIv }
  );

  const wrappedBytes = new Uint8Array(12 + wrappedKeyBuf.byteLength);
  wrappedBytes.set(wrapIv, 0);
  wrappedBytes.set(new Uint8Array(wrappedKeyBuf), 12);

  const exportedEphemeralPub = await exportPublicKey(ephemeralPair.publicKey);

  return {
    wrappedFileKey: bytesToHex(wrappedBytes),
    ephemeralPublicKey: exportedEphemeralPub
  };
}

// ==========================================
// Phase 4: Auditable Hash Chain
// ==========================================

/**
 * Hashes a string using standard SHA-256 and returns a hex string.
 * Used for verifying the Audit Chain locally.
 */
export async function hashSHA256(text: string): Promise<string> {
  const enc = new TextEncoder();
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', enc.encode(text));
  return bytesToHex(new Uint8Array(hashBuffer));
}

// ==========================================
// Phase 5: Receiver Decryption Utilities
// ==========================================

export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

export async function decryptFileKeyWithX3DH(
  wrappedFileKeyHex: string,
  ephemeralPublicKeyHex: string,
  senderIdentityKeyHex: string,
  recipientIdentityPrivateKey: CryptoKey,
  encryptedPrivatePreKeyHex: string,
  preKeyIvHex: string,
  kek: CryptoKey
): Promise<CryptoKey> {
  // 1. Unwrap Bob's private pre-key
  const privatePreKey = await window.crypto.subtle.unwrapKey(
    "pkcs8",
    hexToBytes(encryptedPrivatePreKeyHex) as any,
    kek,
    { name: "AES-GCM", iv: hexToBytes(preKeyIvHex) as any },
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"]
  );

  // 2. Import Alice's Public Keys
  const ephemeralPubKey = await importPublicKey(ephemeralPublicKeyHex);
  const senderIdentityKey = await importPublicKey(senderIdentityKeyHex);

  // 3. X3DH Reciprocal Math
  const dh1 = await deriveRawSecret(privatePreKey, senderIdentityKey);
  const dh2 = await deriveRawSecret(recipientIdentityPrivateKey, ephemeralPubKey);
  const dh3 = await deriveRawSecret(privatePreKey, ephemeralPubKey);

  const combined = new Uint8Array(dh1.length + dh2.length + dh3.length);
  combined.set(dh1, 0);
  combined.set(dh2, dh1.length);
  combined.set(dh3, dh1.length + dh2.length);

  // SHA-256 KDF
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', combined);
  const sharedKek = await window.crypto.subtle.importKey(
    "raw",
    hashBuffer,
    { name: "AES-GCM" },
    false,
    ["unwrapKey"]
  );

  // 4. Unwrap the file key
  const fullWrappedBytes = hexToBytes(wrappedFileKeyHex);
  const wrapIv = fullWrappedBytes.slice(0, 12);
  const wrappedKeyOnly = fullWrappedBytes.slice(12);

  return window.crypto.subtle.unwrapKey(
    "raw",
    wrappedKeyOnly,
    sharedKek,
    { name: "AES-GCM", iv: wrapIv },
    { name: "AES-GCM", length: 256 },
    true,
    ["decrypt"]
  );
}

export async function decryptFileData(fileKey: CryptoKey, ciphertextHex: string, ivHex: string): Promise<string> {
  const cipherBytes = hexToBytes(ciphertextHex);
  const ivBytes = hexToBytes(ivHex);

  const plainBytes = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: ivBytes as any },
    fileKey,
    cipherBytes as any
  );

  return new TextDecoder().decode(plainBytes);
}

// ==========================================
// Phase 6: Chunked Stream Support
// ==========================================

export async function encryptFileChunked(fileKey: CryptoKey, file: File): Promise<{ encryptedBlob: Blob, fileIv: string }> {
  const CHUNK_SIZE = 1024 * 1024 * 5; // 5MB chunks
  const encryptedChunks: Blob[] = [];
  let offset = 0;
  
  // Base IV for tracking
  const fileIv = bytesToHex(window.crypto.getRandomValues(new Uint8Array(12)));

  while (offset < file.size) {
    const chunk = file.slice(offset, offset + CHUNK_SIZE);
    const chunkBuffer = await chunk.arrayBuffer();
    
    const chunkIv = window.crypto.getRandomValues(new Uint8Array(12));
    const encryptedArrayBuffer = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: chunkIv },
      fileKey,
      chunkBuffer
    );
    
    // Combine chunkIv and encrypted buffer
    encryptedChunks.push(new Blob([chunkIv, encryptedArrayBuffer]));
    
    offset += CHUNK_SIZE;
  }
  
  return {
    encryptedBlob: new Blob(encryptedChunks),
    fileIv 
  };
}

export async function decryptFileChunked(fileKey: CryptoKey, encryptedBlob: Blob): Promise<Blob> {
  const ENCRYPTED_CHUNK_SIZE = (1024 * 1024 * 5) + 16 + 12; 
  const plainChunks: Blob[] = [];
  let offset = 0;

  while (offset < encryptedBlob.size) {
    const chunk = encryptedBlob.slice(offset, offset + ENCRYPTED_CHUNK_SIZE);
    const chunkBuffer = await chunk.arrayBuffer();
    
    // Extract IV (first 12 bytes)
    const iv = chunkBuffer.slice(0, 12);
    const ciphertext = chunkBuffer.slice(12);
    
    const decryptedBuffer = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      fileKey,
      ciphertext
    );
    
    plainChunks.push(new Blob([decryptedBuffer]));
    offset += ENCRYPTED_CHUNK_SIZE;
  }

  return new Blob(plainChunks);
}
