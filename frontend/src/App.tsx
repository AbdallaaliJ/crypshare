import { useEffect, useState } from "react";

function App() {
  const [status, setStatus] = useState<string>("loading...");

  useEffect(() => {
    fetch("http://localhost:3001/health")
      .then(res => res.json())
      .then(data => setStatus(data.status))
      .catch(() => setStatus("backend not reachable"));
  }, []);

  return (
    <div style={{ padding: "2rem", fontFamily: "sans-serif" }}>
      <h1>CrypShare</h1>
      <p>Backend status: <strong>{status}</strong></p>
    </div>
  );
}

export default App;
