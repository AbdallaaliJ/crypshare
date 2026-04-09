import express from "express";
import cors from "cors";
import crypto from "crypto";
import multer from "multer";
import path from "path";
import fs from "fs";

const uploadMiddleware = multer({ dest: path.join(__dirname, '../uploads') });
const app = express();
const PORT = 3001;

app.use(cors());
app.use(express.json());

// In-memory "Safe Deposit Box"
// In a real app this would be Postgres/MongoDB
const database: Record<string, any> = {};

// --- Phase 4: Auditable Hash Chain ---
interface AuditEntry {
  timestamp: number;
  userId: string;
  action: string;
  previousHash: string;
  hash: string;
}
const auditLog: AuditEntry[] = [];
const GENESIS_HASH = "0".repeat(64);

function appendAuditLog(userId: string, action: string) {
  const previousHash = auditLog.length === 0 ? GENESIS_HASH : auditLog[auditLog.length - 1].hash;
  const timestamp = Date.now();
  
  const payload = JSON.stringify([timestamp, userId, action]) + previousHash;
  const hash = crypto.createHash('sha256').update(payload).digest('hex');
  
  auditLog.push({ timestamp, userId, action, previousHash, hash });
  console.log(`[AUDIT LOG] ${action} -> [Hash: ${hash.substring(0, 8)}...]`);
}
// -------------------------------------

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

app.post("/register", (req, res) => {
  const { username, salt, publicKey, encryptedPrivateKey, iv } = req.body;
  if (!username || !salt || !publicKey || !encryptedPrivateKey || !iv) {
    res.status(400).json({ error: "Missing required fields" });
    return;
  }

  // Store simply in memory
  database[username] = {
    salt,
    publicKey,
    encryptedPrivateKey,
    iv,
    preKeys: [],
    inbox: []
  };

  appendAuditLog(username, "Identity Registration");

  console.log(`Registered user: ${username}`);
  console.log(`Stored Identity payload keys:`, Object.keys(database[username]));

  res.json({ message: "Identity securely deposited", databaseState: database[username] });
});

app.post("/upload-prekeys", (req, res) => {
  const { username, preKeys } = req.body;
  if (!username || !preKeys || !Array.isArray(preKeys)) {
    res.status(400).json({ error: "Missing username or preKeys array" });
    return;
  }
  if (!database[username]) {
    res.status(404).json({ error: "User not found" });
    return;
  }

  database[username].preKeys = preKeys;
  console.log(`Stored ${preKeys.length} One-Time Pre-Keys for user ${username}`);
  res.json({ message: "Pre-Keys safely uploaded!" });
});

app.get("/prekey/:username", (req, res) => {
  const { username } = req.params;
  const userRecord = database[username];
  
  if (!userRecord) {
    res.status(404).json({ error: "User not found" });
    return;
  }
  
  if (!userRecord.preKeys || userRecord.preKeys.length === 0) {
    res.status(404).json({ error: "No pre-keys available for this user" });
    return;
  }

  // Find an unconsumed pre-key
  const unconsumedIdx = userRecord.preKeys.findIndex((k: any) => !k.consumed);
  if (unconsumedIdx === -1) {
    res.status(404).json({ error: "No pre-keys available for this user" });
    return;
  }

  const preKey = userRecord.preKeys[unconsumedIdx];
  userRecord.preKeys[unconsumedIdx].consumed = true;
  
  const remaining = userRecord.preKeys.filter((k: any) => !k.consumed).length;
  console.log(`Issued One-Time Pre-Key for ${username}. Remaining: ${remaining}`);
  
  // Return only the public part
  res.json({ preKey: { publicKeyHex: preKey.publicKeyHex } });
});

app.get("/users", (req, res) => {
  const users = Object.keys(database).map(username => ({
    username,
    publicKey: database[username].publicKey
  }));
  res.json(users);
});

app.post("/upload", uploadMiddleware.single("fileBlob"), (req, res) => {
  const { recipientUsername, fileIv, wrappedFileKey, ephemeralPublicKey, usedPreKey, originalFilename } = req.body;
  if (!recipientUsername || !req.file || !fileIv || !wrappedFileKey || !ephemeralPublicKey || !usedPreKey) {
    res.status(400).json({ error: "Missing file package components" });
    return;
  }
  if (!database[recipientUsername]) {
    res.status(404).json({ error: "Recipient not found" });
    return;
  }
  
  console.log(`\n--- NEW FILE UPLOAD ---`);
  console.log(`Target Recipient: ${recipientUsername}`);
  console.log(`Encrypted Data Path: ${req.file.path} (Simulated Disk Storage)`);
  console.log(`Wrapped File Key (Hex): ${wrappedFileKey}`);
  console.log(`Ephemeral Sender PubKey: ${ephemeralPublicKey.slice(0, 30)}...`);
  console.log(`Used Recipient Pre-Key: ${usedPreKey.slice(0, 30)}...`);
  console.log(`-----------------------\n`);

  // Locate the specific private key data for Bob to decrypt later
  const matchingPreKey = database[recipientUsername].preKeys.find((k: any) => k.publicKeyHex === usedPreKey);
  
  database[recipientUsername].inbox = database[recipientUsername].inbox || [];
  database[recipientUsername].inbox.push({
    filepath: req.file.filename,
    originalFilename: originalFilename || "EncryptedFile.bin",
    fileSize: req.file.size,
    fileIv,
    wrappedFileKey,
    ephemeralPublicKey,
    usedPreKey,
    encryptedPrivatePreKey: matchingPreKey ? matchingPreKey.encryptedPrivateKey : null,
    preKeyIv: matchingPreKey ? matchingPreKey.iv : null,
    timestamp: Date.now()
  });

  appendAuditLog(recipientUsername, "File Package Encrypted & Uploaded");

  res.json({ message: "File accurately packaged and securely uploaded!" });
});

app.get("/audit-log", (req, res) => {
  res.json(auditLog);
});

app.get("/inbox/:username", (req, res) => {
  const { username } = req.params;
  const userRecord = database[username];
  if (!userRecord) {
    res.status(404).json({ error: "User not found" });
    return;
  }
  res.json({ inbox: userRecord.inbox || [], salt: userRecord.salt });
});

app.get("/download-file/:filename", (req, res) => {
  const filepath = path.join(__dirname, "../uploads", req.params.filename);
  if (!fs.existsSync(filepath)) {
    res.status(404).json({ error: "File not found" });
    return;
  }
  res.download(filepath);
});

app.listen(PORT, () => {
  console.log(`Backend running on http://localhost:${PORT}`);
});
