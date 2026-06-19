import net from "node:net";

const DEFAULT_TURN_URLS = "turn:127.0.0.1:3478?transport=tcp,turn:127.0.0.1:3478?transport=udp";
const TURN_URLS = (process.env.P2P_TURN_URLS || DEFAULT_TURN_URLS)
  .split(",")
  .map((url) => url.trim())
  .filter(Boolean);

function parseTurnUrl(rawUrl: string) {
  const normalized = rawUrl.startsWith("turn:") || rawUrl.startsWith("turns:")
    ? rawUrl.replace(/^turns?:/, "turn://")
    : rawUrl;
  const parsed = new URL(normalized);
  return {
    rawUrl,
    host: parsed.hostname,
    port: Number(parsed.port || "3478"),
    transport: parsed.searchParams.get("transport") || "udp"
  };
}

function checkTcp(host: string, port: number, timeoutMs = 3000) {
  return new Promise<void>((resolve, reject) => {
    const socket = net.createConnection({ host, port });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`Timed out connecting to ${host}:${port}.`));
    }, timeoutMs);

    socket.once("connect", () => {
      clearTimeout(timer);
      socket.end();
      resolve();
    });
    socket.once("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

async function main() {
  const checks = TURN_URLS.map(parseTurnUrl);
  const tcpChecks = checks.filter((check) => check.transport === "tcp");

  if (tcpChecks.length === 0) {
    console.warn("No TCP TURN URL is configured. Browser relay-only P2P may fail on networks that block UDP.");
    return;
  }

  for (const check of tcpChecks) {
    await checkTcp(check.host, check.port);
    console.log(`TURN TCP reachable: ${check.host}:${check.port} (${check.rawUrl})`);
  }

  console.log("TURN TCP reachability check passed. Use the in-app TURN self-test to verify browser relay candidates.");
}

main().catch((err) => {
  console.error("TURN reachability check failed.");
  console.error(err instanceof Error ? err.message : err);
  process.exitCode = 1;
});
