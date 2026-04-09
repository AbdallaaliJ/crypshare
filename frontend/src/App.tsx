import { useEffect, useState } from "react";
import { generateSalt, deriveKEK, bytesToHex, generateIdentityKeyPair, wrapPrivateKey, exportPublicKey, generateFileKey, encryptFileChunked, encryptFileKeyWithPreKey, generatePreKeys, hashSHA256, decryptFileKeyWithPreKey, decryptFileChunked } from "./utils/crypto";

function App() {
  const [status, setStatus] = useState<string>("loading...");
  const [password, setPassword] = useState("");
  const [username, setUsername] = useState("");
  const [dbState, setDbState] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  
  // Phase 2 State
  const [users, setUsers] = useState<{username: string, publicKey: string}[]>([]);
  const [recipient, setRecipient] = useState("");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  // Phase 4 State
  const [auditLogStatus, setAuditLogStatus] = useState<{message: string, valid: boolean} | null>(null);
  const [auditChain, setAuditChain] = useState<any[]>([]);

  // Phase 5 State
  const [inboxUsername, setInboxUsername] = useState("");
  const [inboxPassword, setInboxPassword] = useState("");
  const [inboxFiles, setInboxFiles] = useState<any[]>([]);
  const [decryptedFiles, setDecryptedFiles] = useState<Record<number, string>>({});

  const loadUsers = async () => {
    try {
      const r = await fetch("http://localhost:3001/users");
      const data = await r.json();
      setUsers(data);
      if (data.length > 0 && !recipient) setRecipient(data[0].username);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetch("http://localhost:3001/health")
      .then(res => res.json())
      .then(data => setStatus(data.status))
      .catch(() => setStatus("backend not reachable"));
  }, []);

  const handleRegisterIdentity = async () => {
    if (!password || !username) {
      alert("Please enter a username and password");
      return;
    }
    
    setLoading(true);
    setDbState(null);
    try {
      // Step 1: Derive KEK
      const salt = generateSalt();
      const kek = await deriveKEK(password, salt);
      
      // Step 2: Generate Identity (ECDH)
      const keyPair = await generateIdentityKeyPair();
      const publicKeyHex = await exportPublicKey(keyPair.publicKey);

      // Step 3: Wrap Private Key with AES-GCM
      const { ciphertext, iv } = await wrapPrivateKey(kek, keyPair.privateKey);

      // Step 4: Send to Server (Safe Deposit Box)
      const payload = {
        username,
        salt: bytesToHex(salt),
        publicKey: publicKeyHex,
        encryptedPrivateKey: ciphertext,
        iv
      };

      const res = await fetch("http://localhost:3001/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      
      const json = await res.json();
      
      if (res.ok) {
        setStatus("generating pre-keys...");
        
        // Phase 3: Generate and Upload Pre-Keys
        const preKeys = await generatePreKeys(kek, 100);
        await fetch("http://localhost:3001/upload-prekeys", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, preKeys })
        });
        
        json.databaseState.preKeysCount = 100; // Display purpose
        setDbState(json.databaseState);
        setStatus("ok");
      } else {
        alert(json.error);
      }
    } catch (err) {
      console.error(err);
      alert("Error generating identity.");
    } finally {
      setLoading(false);
    }
  }

  const handleSendSecureFile = async () => {
    if (!recipient || !selectedFile) {
      alert("Select a recipient and attach a file.");
      return;
    }

    try {
      setLoading(true);
      const targetUser = users.find(u => u.username === recipient);
      if (!targetUser) return;

      // 1. Generate random AES-GCM 256 File Key
      const fileKey = await generateFileKey();

      // 2. Encrypt the file logic chunked
      setStatus("encrypting chunks...");
      const { encryptedBlob, fileIv } = await encryptFileChunked(fileKey, selectedFile);

      // Phase 3: Fetch One-Time Pre-Key
      setStatus("fetching pre-key...");
      const preKeyRes = await fetch(`http://localhost:3001/prekey/${recipient}`);
      const preKeyJson = await preKeyRes.json();
      if (!preKeyRes.ok) {
        alert(preKeyJson.error || "Failed to fetch pre-key. User might be out of pre-keys!");
        setLoading(false);
        return;
      }
      const usedPreKey = preKeyJson.preKey.publicKeyHex;

      // 3. ECIES: Key Agreement & Wrapping WITH Pre-Key
      const { wrappedFileKey, ephemeralPublicKey } = await encryptFileKeyWithPreKey(fileKey, usedPreKey);

      // 4. Send the encapsulated package via FormData
      setStatus("uploading...");
      const formData = new FormData();
      formData.append("recipientUsername", recipient);
      formData.append("ephemeralPublicKey", ephemeralPublicKey);
      formData.append("usedPreKey", usedPreKey);
      formData.append("wrappedFileKey", wrappedFileKey);
      formData.append("fileIv", fileIv);
      formData.append("originalFilename", selectedFile.name);
      formData.append("fileBlob", encryptedBlob, selectedFile.name + ".bin");

      const res = await fetch("http://localhost:3001/upload", {
        method: "POST",
        body: formData
      });

      const json = await res.json();
      if (res.ok) {
        alert(json.message);
        setSelectedFile(null); // Clear input conceptually in react
        console.log("Transmission Successful");
      } else {
        alert(json.error);
      }
    } catch(err) {
      console.error(err);
      alert("Encryption error.");
    } finally {
      setStatus("ok");
      setLoading(false);
    }
  }

  const handleVerifyLogs = async () => {
    try {
      setLoading(true);
      setAuditLogStatus(null);
      const r = await fetch("http://localhost:3001/audit-log");
      const logs = await r.json();
      setAuditChain(logs);

      if (logs.length === 0) {
        setAuditLogStatus({ message: "No logs strictly found.", valid: true });
        return;
      }

      const GENESIS_HASH = "0".repeat(64);
      let previousHash = GENESIS_HASH;
      let allValid = true;

      for (let i = 0; i < logs.length; i++) {
        const entry = logs[i];
        
        // Ensure the chain linkage is correct
        if (entry.previousHash !== previousHash) {
          allValid = false;
          break;
        }

        const payload = JSON.stringify([entry.timestamp, entry.userId, entry.action]) + previousHash;
        const computedHash = await hashSHA256(payload);

        if (computedHash !== entry.hash) {
          console.error("Hash mismatch at index", i, "computed:", computedHash, "server:", entry.hash);
          allValid = false;
          break;
        }

        previousHash = entry.hash;
      }

      if (allValid) {
        setAuditLogStatus({ message: "Verification Successful: Log is mathematically untampered.", valid: true });
      } else {
        setAuditLogStatus({ message: "Verification Failed: Audit Log Tampered!", valid: false });
      }
    } catch(err) {
      console.error(err);
      setAuditLogStatus({ message: "Error verifying logs.", valid: false });
    } finally {
      setLoading(false);
    }
  };

  const handleFetchInbox = async () => {
    if (!inboxUsername) return;
    try {
      const r = await fetch(`http://localhost:3001/inbox/${inboxUsername}`);
      const data = await r.json();
      if (!r.ok) {
        alert(data.error || "Failed to fetch inbox");
        return;
      }
      setInboxFiles(data.inbox.map((file: any) => ({ ...file, salt: data.salt })));
    } catch(err) {
      console.error(err);
      alert("Error fetching inbox.");
    }
  };

  const handleDecryptFile = async (idx: number, filePayload: any) => {
    if (!inboxPassword) {
      alert("Please enter your password to unlock the private key.");
      return;
    }
    try {
      setLoading(true);
      // 1. Derive KEK
      // Convert salt from hex to Uint8Array
      const saltBytes = new Uint8Array(filePayload.salt.match(/.{1,2}/g)!.map((byte: string) => parseInt(byte, 16)));
      const kek = await deriveKEK(inboxPassword, saltBytes);

      // 2. Unwrap File Key using Pre-Key
      const fileKey = await decryptFileKeyWithPreKey(
        filePayload.wrappedFileKey,
        filePayload.ephemeralPublicKey,
        filePayload.encryptedPrivatePreKey,
        filePayload.preKeyIv,
        kek
      );

      // 3. Fetch encrypted buffer and decrypt
      const blobRes = await fetch(`http://localhost:3001/download-file/${filePayload.filepath}`);
      if (!blobRes.ok) {
        alert("Encrypted file not found on server storage.");
        setLoading(false);
        return;
      }
      const encryptedBlob = await blobRes.blob();
      
      const plainBlob = await decryptFileChunked(fileKey, encryptedBlob);
      const url = URL.createObjectURL(plainBlob);

      setDecryptedFiles(prev => ({ ...prev, [idx]: url }));
    } catch(err) {
      console.error("Decryption failed", err);
      alert("Failed to decrypt. Wrong password or corrupted package.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ padding: "2rem", fontFamily: "sans-serif", display: "flex", gap: "2rem" }}>
      <div style={{ flex: 1 }}>
        <h1>CrypShare</h1>
      <p>Backend status: <strong>{status}</strong></p>

      <div style={{ marginTop: "2rem", padding: "1rem", border: "1px solid #ccc", borderRadius: "8px" }}>
        <h2>Zero-Knowledge Registration (Steps 1-4)</h2>
        <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem", maxWidth: "300px" }}>
          <input 
            type="text" 
            placeholder="Username" 
            value={username}
            onChange={e => setUsername(e.target.value)}
            style={{ padding: "0.5rem" }}
          />
          <input 
            type="password" 
            placeholder="Test Password" 
            value={password}
            onChange={e => setPassword(e.target.value)}
            style={{ padding: "0.5rem" }}
          />
          <button 
            disabled={loading}
            onClick={handleRegisterIdentity} 
            style={{ padding: "0.5rem 1rem", cursor: loading ? "not-allowed" : "pointer" }}
          >
            {loading ? "Generating..." : "Register Identity"}
          </button>
        </div>
        
        {dbState && (
          <div style={{ marginTop: "1rem", background: "#f0f0f0", padding: "1rem", borderRadius: "4px" }}>
            <h3 style={{ marginTop: 0 }}>Backend Storage State</h3>
            <p style={{ fontSize: "0.9rem", color: "#555" }}>
              The server safely holds this payload without knowing your password or your plaintext private key.
            </p>
            <pre style={{ overflowX: "auto", fontSize: "0.85rem" }}>
              {JSON.stringify(dbState, null, 2)}
            </pre>
          </div>
        )}
      </div>
     </div>

      <div style={{ flex: 1, marginTop: "6rem", padding: "1rem", border: "1px solid #ccc", borderRadius: "8px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <h2>Phase 2: Hybrid Encryption</h2>
          <button onClick={loadUsers} style={{ cursor: "pointer", height: "fit-content" }}>Refresh Directory</button>
        </div>
        
        {users.length === 0 ? (
          <p style={{ color: "#777" }}>No users registered on server. Please use Phase 1 first!</p>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
            <label>Recipient:</label>
            <select 
              value={recipient} 
              onChange={e => setRecipient(e.target.value)}
              style={{ padding: "0.5rem" }}
            >
              <option value="">Select a user...</option>
              {users.map(u => <option key={u.username} value={u.username}>{u.username}</option>)}
            </select>
            
            <label>Secure Content (Upload Binary):</label>
            <input 
              type="file" 
              onChange={e => setSelectedFile(e.target.files ? e.target.files[0] : null)}
              style={{ padding: "0.5rem" }}
            />
            
            <button 
              disabled={loading}
              onClick={handleSendSecureFile} 
              style={{ padding: "0.5rem 1rem", cursor: loading ? "not-allowed" : "pointer" }}
            >
              {loading ? "Encrypting..." : "Hybrid Encrypt & Send"}
            </button>
            <p style={{ fontSize: "0.85rem", color: "green" }}>Open Console to see payload details when sending.</p>
          </div>
        )}

        <div style={{ marginTop: "2rem", paddingTop: "1rem", borderTop: "1px solid #ccc" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <h2>Phase 4: System Audit & Verification</h2>
          </div>
          <button 
            disabled={loading}
            onClick={handleVerifyLogs} 
            style={{ padding: "0.5rem 1rem", cursor: loading ? "not-allowed" : "pointer", width: "100%" }}
          >
            {loading ? "Verifying..." : "Download & Verify Audit Logs"}
          </button>

          {auditLogStatus && (
            <div style={{ marginTop: "1rem", padding: "1rem", background: auditLogStatus.valid ? "#e6ffe6" : "#ffe6e6", border: `1px solid ${auditLogStatus.valid ? "green" : "red"}` }}>
              <strong>{auditLogStatus.message}</strong>
            </div>
          )}

          {auditChain.length > 0 && (
            <div style={{ marginTop: "1rem", maxHeight: "200px", overflowY: "auto", fontSize: "0.8rem", background: "#f0f0f0", padding: "0.5rem", borderRadius: "4px" }}>
              {auditChain.map((entry, idx) => (
                <div key={idx} style={{ marginBottom: "0.5rem", borderBottom: "1px solid #ddd", paddingBottom: "0.5rem" }}>
                  <div><strong>Action:</strong> {entry.action}</div>
                  <div><strong>User:</strong> {entry.userId}</div>
                  <div><strong>Prev:</strong> <span style={{ fontFamily: "monospace" }}>{entry.previousHash.slice(0, 16)}...</span></div>
                  <div><strong>Hash:</strong> <span style={{ fontFamily: "monospace", color: "green" }}>{entry.hash.slice(0, 16)}...</span></div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Phase 5 */}
        <div style={{ marginTop: "2rem", paddingTop: "1rem", borderTop: "1px solid #ccc" }}>
          <h2>Phase 5: Recipient Decryption Dashboard</h2>
          <div style={{ display: "flex", gap: "0.5rem", marginBottom: "1rem" }}>
            <input 
              type="text" 
              placeholder="Bob's Username" 
              value={inboxUsername}
              onChange={e => setInboxUsername(e.target.value)}
              style={{ padding: "0.5rem", flex: 1 }}
            />
            <input 
              type="password" 
              placeholder="Bob's Password" 
              value={inboxPassword}
              onChange={e => setInboxPassword(e.target.value)}
              style={{ padding: "0.5rem", flex: 1 }}
            />
            <button onClick={handleFetchInbox} style={{ padding: "0.5rem 1rem", cursor: "pointer" }}>Fetch Inbox</button>
          </div>

          {inboxFiles.length > 0 ? (
            <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
              {inboxFiles.map((file, idx) => (
                <div key={idx} style={{ padding: "1rem", border: "1px dashed #777", borderRadius: "8px", background: "#fafafa", wordBreak: "break-all" }}>
                  <div style={{ fontSize: "0.85rem", color: "#555", marginBottom: "1rem" }}>
                    <strong>Time:</strong> {new Date(file.timestamp).toLocaleString()} <br/>
                    <strong>Filename:</strong> {file.originalFilename} ({(file.fileSize / 1024 / 1024).toFixed(2)} MB)
                  </div>
                  {decryptedFiles[idx] ? (
                    <div style={{ background: "#e6ffe6", padding: "1rem", border: "1px solid green", borderRadius: "4px" }}>
                      <strong style={{ color: "green" }}>Decryption Complete!</strong>
                      <div style={{ marginTop: "1rem" }}>
                        <a 
                          href={decryptedFiles[idx]} 
                          download={file.originalFilename} 
                          style={{ padding: "0.5rem 1rem", backgroundColor: "green", color: "white", textDecoration: "none", borderRadius: "4px", display: "inline-block" }}
                        >
                          Download {file.originalFilename}
                        </a>
                      </div>
                    </div>
                  ) : (
                    <button 
                      onClick={() => handleDecryptFile(idx, file)}
                      style={{ padding: "0.5rem 1rem", backgroundColor: "#333", color: "white", border: "none", borderRadius: "4px", cursor: "pointer" }}
                    >
                      Unlock & Decrypt File
                    </button>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <p style={{ color: "#777", fontSize: "0.9rem" }}>No encrypted files in inbox.</p>
          )}
        </div>
      </div>

    </div>
  );
}

export default App;
