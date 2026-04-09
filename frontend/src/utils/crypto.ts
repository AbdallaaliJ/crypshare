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

export async function encryptFileKeyWithPreKey(fileKey: CryptoKey, recipientPreKeyHex: string): Promise<{ wrappedFileKey: string, ephemeralPublicKey: string }> {
  // Convert the hex Pre-Key into a usable CryptoKey
  const recipientPreKey = await importPublicKey(recipientPreKeyHex);
  
  // Alice generates her Ephemeral KeyPair
  const ephemeralPair = await generateIdentityKeyPair();

  // Create Shared Secret using (Alice Ephemeral Private + Bob Public Pre-Key)
  const sharedKek = await window.crypto.subtle.deriveKey(
    {
      name: "ECDH",
      public: recipientPreKey
    },
    ephemeralPair.privateKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["wrapKey", "unwrapKey"]
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

export async function decryptFileKeyWithPreKey(
  wrappedFileKeyHex: string,
  ephemeralPublicKeyHex: string,
  encryptedPrivatePreKeyHex: string,
  preKeyIvHex: string,
  kek: CryptoKey
): Promise<CryptoKey> {
  // 1. Unwrap Bob's private pre-key
  const privatePreKey = await window.crypto.subtle.unwrapKey(
    "pkcs8",
    hexToBytes(encryptedPrivatePreKeyHex),
    kek,
    { name: "AES-GCM", iv: hexToBytes(preKeyIvHex) },
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveKey", "deriveBits"]
  );

  // 2. Import Alice's Ephemeral Public Key
  const ephemeralPubKey = await importPublicKey(ephemeralPublicKeyHex);

  // 3. Derive Shared Secret (DH)
  const sharedKek = await window.crypto.subtle.deriveKey(
    {
      name: "ECDH",
      public: ephemeralPubKey
    },
    privatePreKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["unwrapKey"]
  );

  // 4. Unwrap the file key
  // Remember: wrapIv was prepended to wrappedKeyBuf (12 bytes)
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
    ["decrypt"] // we only need it for decryption now
  );
}

export async function decryptFileData(fileKey: CryptoKey, ciphertextHex: string, ivHex: string): Promise<string> {
  const cipherBytes = hexToBytes(ciphertextHex);
  const ivBytes = hexToBytes(ivHex);

  const plainBytes = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: ivBytes },
    fileKey,
    cipherBytes
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
