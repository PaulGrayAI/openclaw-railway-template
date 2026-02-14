import childProcess from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import express from "express";
import httpProxy from "http-proxy";
import * as tar from "tar";

// Railway commonly sets PORT=8080 for HTTP services.
const PORT = Number.parseInt(process.env.PORT ?? "8080", 10);
const STATE_DIR =
  process.env.OPENCLAW_STATE_DIR?.trim() ||
  path.join(os.homedir(), ".openclaw");
const WORKSPACE_DIR =
  process.env.OPENCLAW_WORKSPACE_DIR?.trim() ||
  path.join(STATE_DIR, "workspace");

// Protect /setup with a user-provided password.
const SETUP_PASSWORD = process.env.SETUP_PASSWORD?.trim();

// Debug logging helper
const DEBUG = process.env.OPENCLAW_TEMPLATE_DEBUG?.toLowerCase() === "true";
function debug(...args) {
  if (DEBUG) console.log(...args);
}

// Gateway admin token (protects Openclaw gateway + Control UI).
// Must be stable across restarts. If not provided via env, persist it in the state dir.
function resolveGatewayToken() {
  const envTok = process.env.OPENCLAW_GATEWAY_TOKEN?.trim();
  if (envTok) {
    console.log(`[token] Using token from OPENCLAW_GATEWAY_TOKEN env variable`);
    return envTok;
  }

  const tokenPath = path.join(STATE_DIR, "gateway.token");
  try {
    const existing = fs.readFileSync(tokenPath, "utf8").trim();
    if (existing) {
      console.log(`[token] Using token from persisted file`);
      return existing;
    }
  } catch {}

  const generated = crypto.randomBytes(32).toString("hex");
  console.log(`[token] Generated new random token`);
  try {
    fs.mkdirSync(STATE_DIR, { recursive: true });
    fs.writeFileSync(tokenPath, generated, { encoding: "utf8", mode: 0o600 });
  } catch (err) {
    console.warn(`[token] Could not persist token: ${err}`);
  }
  return generated;
}

const OPENCLAW_GATEWAY_TOKEN = resolveGatewayToken();
process.env.OPENCLAW_GATEWAY_TOKEN = OPENCLAW_GATEWAY_TOKEN;
console.log(`[token] Final resolved token: ${OPENCLAW_GATEWAY_TOKEN.slice(0, 16)}... (len: ${OPENCLAW_GATEWAY_TOKEN.length})`);
console.log(`[token] ========== TOKEN RESOLUTION COMPLETE ==========\n`);

// Where the gateway will listen internally (we proxy to it).
const INTERNAL_GATEWAY_PORT = Number.parseInt(
  process.env.INTERNAL_GATEWAY_PORT ?? "18789",
  10,
);
const INTERNAL_GATEWAY_HOST = process.env.INTERNAL_GATEWAY_HOST ?? "127.0.0.1";
const GATEWAY_TARGET = `http://${INTERNAL_GATEWAY_HOST}:${INTERNAL_GATEWAY_PORT}`;

// Always run the built-from-source CLI entry directly to avoid PATH/global-install mismatches.
const OPENCLAW_ENTRY =
  process.env.OPENCLAW_ENTRY?.trim() || "/openclaw/dist/entry.js";
const OPENCLAW_NODE = process.env.OPENCLAW_NODE?.trim() || "node";

// Auth choices that require an interactive OAuth device-code flow.
const OAUTH_AUTH_CHOICES = new Set([
  "openai-codex",
  "codex-cli",
  "claude-cli",
  "google-antigravity",
  "google-gemini-cli",
  "github-copilot",
  "qwen-portal",
]);

// --- OpenAI Codex OAuth Device-Code Flow (direct implementation) ---
// This bypasses the CLI's TUI which doesn't work in headless Docker containers.
const OPENAI_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann";
const OPENAI_AUTH_BASE = "https://auth.openai.com";

async function openaiDeviceCodeFlow({ onStatus, signal }) {
  // Step 1: Request device code
  const userCodeResp = await fetch(`${OPENAI_AUTH_BASE}/api/accounts/deviceauth/usercode`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ client_id: OPENAI_CLIENT_ID }),
    signal,
  });
  if (!userCodeResp.ok) {
    const txt = await userCodeResp.text();
    throw new Error(`Device code request failed (${userCodeResp.status}): ${txt}`);
  }
  const deviceData = await userCodeResp.json();
  const { user_code, device_auth_id, verification_uri, verification_uri_complete, interval: pollInterval } = deviceData;

  onStatus({
    type: "device_code",
    userCode: user_code,
    verificationUrl: verification_uri_complete || verification_uri || `${OPENAI_AUTH_BASE}/codex/device`,
    expiresIn: 900,
  });

  // Step 2: Poll for authorization
  const intervalMs = (pollInterval || 5) * 1000;
  const maxWaitMs = 15 * 60 * 1000; // 15 minutes
  const deadline = Date.now() + maxWaitMs;
  let authCode = null;
  let codeVerifier = null;

  while (Date.now() < deadline) {
    if (signal?.aborted) throw new Error("OAuth flow aborted");
    await sleep(intervalMs);

    try {
      const pollResp = await fetch(`${OPENAI_AUTH_BASE}/api/accounts/deviceauth/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ device_auth_id, user_code }),
        signal,
      });

      // Read body once to avoid double-consume
      const pollBody = await pollResp.text();
      let pollData;
      try { pollData = JSON.parse(pollBody); } catch {}

      if (pollResp.status === 403 || pollResp.status === 404) {
        // Still waiting for user to authorize
        onStatus({ type: "polling" });
        continue;
      }

      if (pollResp.ok && (pollData?.authorization_code || pollData?.code)) {
        authCode = pollData.authorization_code || pollData.code;
        codeVerifier = pollData.code_verifier || pollData.code_challenge;
        onStatus({ type: "authorized" });
        break;
      }

      // 200 without auth code, or other status — log details and keep polling
      onStatus({ type: "poll_status", status: pollResp.status, body: pollBody.slice(0, 300) });
    } catch (err) {
      if (signal?.aborted) throw err;
      onStatus({ type: "poll_error", message: String(err) });
    }
  }

  if (!authCode) {
    throw new Error("Device code expired — user did not authorize within 15 minutes");
  }

  // Step 3: Exchange authorization code for tokens
  const tokenResp = await fetch(`${OPENAI_AUTH_BASE}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: OPENAI_CLIENT_ID,
      grant_type: "authorization_code",
      code: authCode,
      code_verifier: codeVerifier || "",
      redirect_uri: `${OPENAI_AUTH_BASE}/deviceauth/callback`,
    }),
    signal,
  });

  if (!tokenResp.ok) {
    const txt = await tokenResp.text();
    throw new Error(`Token exchange failed (${tokenResp.status}): ${txt}`);
  }

  const tokens = await tokenResp.json();
  return {
    accessToken: tokens.access_token,
    refreshToken: tokens.refresh_token,
    expiresIn: tokens.expires_in,
    expiresAt: Date.now() + (tokens.expires_in || 3600) * 1000,
  };
}

function clawArgs(args) {
  return [OPENCLAW_ENTRY, ...args];
}

function configPath() {
  return (
    process.env.OPENCLAW_CONFIG_PATH?.trim() ||
    path.join(STATE_DIR, "openclaw.json")
  );
}

function isConfigured() {
  try {
    return fs.existsSync(configPath());
  } catch {
    return false;
  }
}

let gatewayProc = null;
let gatewayStarting = null;

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function waitForGatewayReady(opts = {}) {
  const timeoutMs = opts.timeoutMs ?? 20_000;
  const start = Date.now();
  const endpoints = ["/openclaw", "/openclaw", "/", "/health"];
  
  while (Date.now() - start < timeoutMs) {
    for (const endpoint of endpoints) {
      try {
        const res = await fetch(`${GATEWAY_TARGET}${endpoint}`, { method: "GET" });
        // Any HTTP response means the port is open.
        if (res) {
          console.log(`[gateway] ready at ${endpoint}`);
          return true;
        }
      } catch (err) {
        // not ready, try next endpoint
      }
    }
    await sleep(250);
  }
  console.error(`[gateway] failed to become ready after ${timeoutMs}ms`);
  return false;
}

// Patch the compiled gateway code to preserve operator scopes when device auth
// is bypassed (allowInsecureAuth or dangerouslyDisableDeviceAuth). Without this,
// the gateway clears all scopes to [] when no device identity is present, causing
// "missing scope: operator.read/write" errors in the Control UI.
function patchGatewayScopes() {
  const gatewayFiles = [
    "/openclaw/dist/gateway-cli-DO7TBq1j.js",
    "/openclaw/dist/gateway-cli-ChsmQYiD.js",
  ];
  // The original code unconditionally clears scopes when !device:
  //   if (!device) { if (scopes.length > 0) { scopes = []; connectParams.scopes = scopes; }
  // We change it to only clear scopes when the bypass is NOT active:
  //   if (!device) { if (scopes.length > 0 && !(allowControlUiBypass && sharedAuthOk)) { scopes = []; ...
  const needle = "if (!device) {\n\t\t\t\t\tif (scopes.length > 0) {\n\t\t\t\t\t\tscopes = [];";
  const replacement = "if (!device) {\n\t\t\t\t\tif (scopes.length > 0 && !(allowControlUiBypass && sharedAuthOk)) {\n\t\t\t\t\t\tscopes = [];";
  for (const filePath of gatewayFiles) {
    try {
      const content = fs.readFileSync(filePath, "utf8");
      if (content.includes(needle)) {
        fs.writeFileSync(filePath, content.replace(needle, replacement));
        console.log(`[patch] Patched scope clearing in ${path.basename(filePath)}`);
      } else if (content.includes(replacement)) {
        console.log(`[patch] Already patched: ${path.basename(filePath)}`);
      } else {
        console.warn(`[patch] Could not find scope-clearing pattern in ${path.basename(filePath)}`);
      }
    } catch (err) {
      console.warn(`[patch] Could not patch ${filePath}: ${err.message}`);
    }
  }
}

async function startGateway() {
  if (gatewayProc) return;
  if (!isConfigured()) throw new Error("Gateway cannot start: not configured");

  fs.mkdirSync(STATE_DIR, { recursive: true });
  fs.mkdirSync(WORKSPACE_DIR, { recursive: true });

  // Sync wrapper token to openclaw.json before every gateway start.
  // This ensures the gateway's config-file token matches what the wrapper injects via proxy.
  console.log(`[gateway] ========== GATEWAY START TOKEN SYNC ==========`);
  console.log(`[gateway] Syncing wrapper token to config: ${OPENCLAW_GATEWAY_TOKEN.slice(0, 16)}... (len: ${OPENCLAW_GATEWAY_TOKEN.length})`);

  const syncResult = await runCmd(
    OPENCLAW_NODE,
    clawArgs(["config", "set", "gateway.auth.token", OPENCLAW_GATEWAY_TOKEN]),
  );

  console.log(`[gateway] Sync result: exit code ${syncResult.code}`);
  if (syncResult.output?.trim()) {
    console.log(`[gateway] Sync output: ${syncResult.output}`);
  }

  if (syncResult.code !== 0) {
    console.error(`[gateway] ⚠️  WARNING: Token sync failed with code ${syncResult.code}`);
  }

  // Verify sync succeeded
  try {
    const config = JSON.parse(fs.readFileSync(configPath(), "utf8"));
    const configToken = config?.gateway?.auth?.token;

    console.log(`[gateway] Token verification:`);
    console.log(`[gateway]   Wrapper: ${OPENCLAW_GATEWAY_TOKEN.slice(0, 16)}... (len: ${OPENCLAW_GATEWAY_TOKEN.length})`);
    console.log(`[gateway]   Config:  ${configToken?.slice(0, 16)}... (len: ${configToken?.length || 0})`);

    if (configToken !== OPENCLAW_GATEWAY_TOKEN) {
      console.error(`[gateway] ✗ Token mismatch detected!`);
      console.error(`[gateway]   Full wrapper: ${OPENCLAW_GATEWAY_TOKEN}`);
      console.error(`[gateway]   Full config:  ${configToken || 'null'}`);
      throw new Error(
        `Token mismatch: wrapper has ${OPENCLAW_GATEWAY_TOKEN.slice(0, 16)}... but config has ${(configToken || 'null')?.slice?.(0, 16)}...`
      );
    }
    console.log(`[gateway] ✓ Token verification PASSED`);
  } catch (err) {
    console.error(`[gateway] ERROR: Token verification failed: ${err}`);
    throw err; // Don't start gateway with mismatched token
  }

  // Ensure trustedProxies includes loopback so the gateway honours X-Forwarded-* from the wrapper
  await runCmd(
    OPENCLAW_NODE,
    clawArgs(["config", "set", "--json", "gateway.trustedProxies", '["127.0.0.1","::1"]']),
  );
  // Ensure Control UI auth settings are present for behind-proxy operation
  await runCmd(
    OPENCLAW_NODE,
    clawArgs(["config", "set", "--json", "gateway.controlUi.allowInsecureAuth", "true"]),
  );
  await runCmd(
    OPENCLAW_NODE,
    clawArgs(["config", "set", "--json", "gateway.controlUi.dangerouslyDisableDeviceAuth", "true"]),
  );
  await runCmd(
    OPENCLAW_NODE,
    clawArgs(["config", "set", "--json", "gateway.controlUi.insecureScopes", '["operator.admin","operator.read","operator.write","operator.approvals","operator.pairing"]']),
  );

  console.log(`[gateway] token sync complete`);

  // Ensure agent auth directory has credentials (copied from main state dir).
  // The onboard --auth-choice skip flow doesn't populate agents/main/agent/,
  // causing "No API key found" errors when the gateway agent tries to use an LLM.
  const agentAuthDir = path.join(STATE_DIR, "agents", "main", "agent");
  fs.mkdirSync(agentAuthDir, { recursive: true });
  for (const f of ["auth-profiles.json", "auth.json"]) {
    const src = path.join(STATE_DIR, f);
    const dst = path.join(agentAuthDir, f);
    try {
      if (fs.existsSync(src) && !fs.existsSync(dst)) {
        fs.copyFileSync(src, dst);
        console.log(`[gateway] Copied ${f} to agent auth dir`);
      }
    } catch (err) {
      console.warn(`[gateway] Could not copy ${f} to agent dir: ${err.message}`);
    }
  }

  const args = [
    "gateway",
    "run",
    "--bind",
    "loopback",
    "--port",
    String(INTERNAL_GATEWAY_PORT),
    "--auth",
    "token",
    "--token",
    OPENCLAW_GATEWAY_TOKEN,
  ];

  // Patch gateway dist to not strip scopes when device auth is bypassed.
  // Without this patch, the gateway clears all scopes to [] when no device identity
  // is present (line ~17815), making the Control UI unable to read/write chat.
  // The patch changes the condition to preserve scopes when allowControlUiBypass && sharedAuthOk.
  patchGatewayScopes();

  gatewayProc = childProcess.spawn(OPENCLAW_NODE, clawArgs(args), {
    stdio: "inherit",
    env: {
      ...process.env,
      OPENCLAW_STATE_DIR: STATE_DIR,
      OPENCLAW_WORKSPACE_DIR: WORKSPACE_DIR,
    },
  });

  console.log(`[gateway] starting with command: ${OPENCLAW_NODE} ${clawArgs(args).join(" ")}`);
  console.log(`[gateway] config path: ${configPath()}`);

  gatewayProc.on("error", (err) => {
    console.error(`[gateway] spawn error: ${String(err)}`);
    gatewayProc = null;
  });

  gatewayProc.on("exit", (code, signal) => {
    console.error(`[gateway] exited code=${code} signal=${signal}`);
    gatewayProc = null;
  });
}

async function ensureGatewayRunning() {
  if (!isConfigured()) return { ok: false, reason: "not configured" };
  if (gatewayProc) return { ok: true };
  if (!gatewayStarting) {
    gatewayStarting = (async () => {
      await startGateway();
      const ready = await waitForGatewayReady({ timeoutMs: 20_000 });
      if (!ready) {
        throw new Error("Gateway did not become ready in time");
      }
    })().finally(() => {
      gatewayStarting = null;
    });
  }
  await gatewayStarting;
  return { ok: true };
}

async function restartGateway() {
  console.log("[gateway] Restarting gateway...");

  // Kill gateway process tracked by wrapper
  if (gatewayProc) {
    console.log("[gateway] Killing wrapper-managed gateway process");
    try {
      gatewayProc.kill("SIGTERM");
    } catch {
      // ignore
    }
    gatewayProc = null;
  }

  // Also kill any other gateway processes (e.g., started by onboard command)
  // by finding processes listening on the gateway port
  console.log(`[gateway] Killing any other gateway processes on port ${INTERNAL_GATEWAY_PORT}`);
  try {
    const killResult = await runCmd("pkill", ["-f", "openclaw-gateway"]);
    console.log(`[gateway] pkill result: exit code ${killResult.code}`);
  } catch (err) {
    console.log(`[gateway] pkill failed: ${err.message}`);
  }

  // Give processes time to exit and release the port
  await sleep(1500);

  return ensureGatewayRunning();
}

function requireSetupAuth(req, res, next) {
  if (!SETUP_PASSWORD) {
    return res
      .status(500)
      .type("text/plain")
      .send(
        "SETUP_PASSWORD is not set. Set it in Railway Variables before using /setup.",
      );
  }

  const header = req.headers.authorization || "";
  const [scheme, encoded] = header.split(" ");
  if (scheme !== "Basic" || !encoded) {
    res.set("WWW-Authenticate", 'Basic realm="Openclaw Setup"');
    return res.status(401).send("Auth required");
  }
  const decoded = Buffer.from(encoded, "base64").toString("utf8");
  const idx = decoded.indexOf(":");
  const password = idx >= 0 ? decoded.slice(idx + 1) : "";
  if (password !== SETUP_PASSWORD) {
    res.set("WWW-Authenticate", 'Basic realm="Openclaw Setup"');
    return res.status(401).send("Invalid password");
  }
  return next();
}

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));

// Minimal health endpoint for Railway.
app.get("/setup/healthz", (_req, res) => res.json({ ok: true }));

// Serve static files for setup wizard
app.get("/setup/app.js", requireSetupAuth, (_req, res) => {
  res.type("application/javascript");
  res.sendFile(path.join(process.cwd(), "src", "public", "setup-app.js"));
});

app.get("/setup/styles.css", requireSetupAuth, (_req, res) => {
  res.type("text/css");
  res.sendFile(path.join(process.cwd(), "src", "public", "styles.css"));
});

app.get("/setup", requireSetupAuth, (_req, res) => {
  res.sendFile(path.join(process.cwd(), "src", "public", "setup.html"));
});

// Temporary diagnostic: grep openclaw dist for scope-related code
app.get("/setup/api/grep-scopes", requireSetupAuth, async (_req, res) => {
  const { execSync } = childProcess;
  const results = {};
  const patterns = [
    "operator.read",
    "operator.write",
    "operator\\.admin.*operator\\.approvals",
    "scopes.*operator",
    "insecureScopes",
    "defaultScopes",
    "operatorScopes",
    "allowedScopes",
    "grantedScopes",
  ];
  for (const p of patterns) {
    try {
      const out = execSync(`grep -r -n "${p}" /openclaw/dist/ 2>/dev/null | head -10`, { encoding: "utf8", timeout: 10000 });
      if (out.trim()) results[p] = out.trim().split("\n").map(l => l.slice(0, 300));
    } catch {}
  }
  // Get context around the allowedScopes/pairedScopes check
  try {
    const out = execSync(`grep -n -B5 -A5 "pairedScopes" /openclaw/dist/gateway-cli-DO7TBq1j.js 2>/dev/null | head -80`, { encoding: "utf8", timeout: 10000 });
    if (out.trim()) results["pairedScopes-context"] = out.trim().split("\n").map(l => l.slice(0, 300));
  } catch {}
  // Find how scopes are set when dangerouslyDisableDeviceAuth is true
  try {
    const out = execSync(`grep -n -B3 -A10 "dangerouslyDisableDeviceAuth\\|allowInsecureAuth\\|sharedAuthOk" /openclaw/dist/gateway-cli-DO7TBq1j.js 2>/dev/null | head -100`, { encoding: "utf8", timeout: 10000 });
    if (out.trim()) results["insecure-auth-context"] = out.trim().split("\n").map(l => l.slice(0, 300));
  } catch {}
  // Find where scopes are first assigned to connections
  try {
    const out = execSync(`grep -n -B2 -A5 "scopes.*=.*\\[" /openclaw/dist/gateway-cli-DO7TBq1j.js 2>/dev/null | head -60`, { encoding: "utf8", timeout: 10000 });
    if (out.trim()) results["scope-assignment"] = out.trim().split("\n").map(l => l.slice(0, 300));
  } catch {}
  // Also check the UI assets
  try {
    const out = execSync(`find /openclaw/dist -name "*.html" -o -name "*.js" | head -20`, { encoding: "utf8", timeout: 5000 });
    results["ui-files"] = out.trim().split("\n");
  } catch {}
  // Check control UI specifically
  try {
    const out = execSync(`grep -r -n "operator" /openclaw/dist/ui/ 2>/dev/null | head -20`, { encoding: "utf8", timeout: 10000 });
    if (out.trim()) results["ui-operator"] = out.trim().split("\n").map(l => l.slice(0, 300));
  } catch {}
  res.json(results);
});

app.get("/setup/api/status", requireSetupAuth, async (_req, res) => {
  const version = await runCmd(OPENCLAW_NODE, clawArgs(["--version"]));
  const channelsHelp = await runCmd(
    OPENCLAW_NODE,
    clawArgs(["channels", "add", "--help"]),
  );

  // We reuse Openclaw's own auth-choice grouping logic indirectly by hardcoding the same group defs.
  // This is intentionally minimal; later we can parse the CLI help output to stay perfectly in sync.
  const authGroups = [
    {
      value: "openai",
      label: "OpenAI",
      hint: "Codex OAuth + API key",
      options: [
        { value: "codex-cli", label: "OpenAI Codex OAuth (Codex CLI)" },
        { value: "openai-codex", label: "OpenAI Codex (ChatGPT OAuth)" },
        { value: "openai-api-key", label: "OpenAI API key" },
      ],
    },
    {
      value: "anthropic",
      label: "Anthropic",
      hint: "Claude Code CLI + API key",
      options: [
        { value: "claude-cli", label: "Anthropic token (Claude Code CLI)" },
        { value: "token", label: "Anthropic token (paste setup-token)" },
        { value: "apiKey", label: "Anthropic API key" },
      ],
    },
    {
      value: "google",
      label: "Google",
      hint: "Gemini API key + OAuth",
      options: [
        { value: "gemini-api-key", label: "Google Gemini API key" },
        { value: "google-antigravity", label: "Google Antigravity OAuth" },
        { value: "google-gemini-cli", label: "Google Gemini CLI OAuth" },
      ],
    },
    {
      value: "openrouter",
      label: "OpenRouter",
      hint: "API key",
      options: [{ value: "openrouter-api-key", label: "OpenRouter API key" }],
    },
    {
      value: "ai-gateway",
      label: "Vercel AI Gateway",
      hint: "API key",
      options: [
        { value: "ai-gateway-api-key", label: "Vercel AI Gateway API key" },
      ],
    },
    {
      value: "moonshot",
      label: "Moonshot AI",
      hint: "Kimi K2 + Kimi Code",
      options: [
        { value: "moonshot-api-key", label: "Moonshot AI API key" },
        { value: "kimi-code-api-key", label: "Kimi Code API key" },
      ],
    },
    {
      value: "zai",
      label: "Z.AI (GLM 4.7)",
      hint: "API key",
      options: [{ value: "zai-api-key", label: "Z.AI (GLM 4.7) API key" }],
    },
    {
      value: "minimax",
      label: "MiniMax",
      hint: "M2.1 (recommended)",
      options: [
        { value: "minimax-api", label: "MiniMax M2.1" },
        { value: "minimax-api-lightning", label: "MiniMax M2.1 Lightning" },
      ],
    },
    {
      value: "qwen",
      label: "Qwen",
      hint: "OAuth",
      options: [{ value: "qwen-portal", label: "Qwen OAuth" }],
    },
    {
      value: "copilot",
      label: "Copilot",
      hint: "GitHub + local proxy",
      options: [
        {
          value: "github-copilot",
          label: "GitHub Copilot (GitHub device login)",
        },
        { value: "copilot-proxy", label: "Copilot Proxy (local)" },
      ],
    },
    {
      value: "synthetic",
      label: "Synthetic",
      hint: "Anthropic-compatible (multi-model)",
      options: [{ value: "synthetic-api-key", label: "Synthetic API key" }],
    },
    {
      value: "opencode-zen",
      label: "OpenCode Zen",
      hint: "API key",
      options: [
        { value: "opencode-zen", label: "OpenCode Zen (multi-model proxy)" },
      ],
    },
  ];

  res.json({
    configured: isConfigured(),
    gatewayTarget: GATEWAY_TARGET,
    openclawVersion: version.output.trim(),
    channelsAddHelp: channelsHelp.output,
    authGroups,
    oauthAuthChoices: [...OAUTH_AUTH_CHOICES],
  });
});

function buildOnboardArgs(payload, opts = {}) {
  const args = [
    "onboard",
    ...(opts.interactive ? [] : ["--non-interactive"]),
    "--accept-risk",
    ...(opts.interactive ? [] : ["--json"]),
    "--no-install-daemon",
    "--skip-health",
    "--workspace",
    WORKSPACE_DIR,
    // The wrapper owns public networking; keep the gateway internal.
    "--gateway-bind",
    "loopback",
    "--gateway-port",
    String(INTERNAL_GATEWAY_PORT),
    "--gateway-auth",
    "token",
    "--gateway-token",
    OPENCLAW_GATEWAY_TOKEN,
    "--flow",
    payload.flow || "quickstart",
  ];

  if (payload.authChoice) {
    args.push("--auth-choice", payload.authChoice);

    // Map secret to correct flag for common choices.
    const secret = (payload.authSecret || "").trim();
    const map = {
      "openai-api-key": "--openai-api-key",
      apiKey: "--anthropic-api-key",
      "openrouter-api-key": "--openrouter-api-key",
      "ai-gateway-api-key": "--ai-gateway-api-key",
      "moonshot-api-key": "--moonshot-api-key",
      "kimi-code-api-key": "--kimi-code-api-key",
      "gemini-api-key": "--gemini-api-key",
      "zai-api-key": "--zai-api-key",
      "minimax-api": "--minimax-api-key",
      "minimax-api-lightning": "--minimax-api-key",
      "synthetic-api-key": "--synthetic-api-key",
      "opencode-zen": "--opencode-zen-api-key",
    };
    const flag = map[payload.authChoice];
    if (flag && secret) {
      args.push(flag, secret);
    }

    if (payload.authChoice === "token" && secret) {
      // This is the Anthropics setup-token flow.
      args.push("--token-provider", "anthropic", "--token", secret);
    }
  }

  return args;
}

function runCmd(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    const proc = childProcess.spawn(cmd, args, {
      ...opts,
      env: {
        ...process.env,
        OPENCLAW_STATE_DIR: STATE_DIR,
        OPENCLAW_WORKSPACE_DIR: WORKSPACE_DIR,
      },
    });

    let out = "";
    proc.stdout?.on("data", (d) => (out += d.toString("utf8")));
    proc.stderr?.on("data", (d) => (out += d.toString("utf8")));

    proc.on("error", (err) => {
      out += `\n[spawn error] ${String(err)}\n`;
      resolve({ code: 127, output: out });
    });

    proc.on("close", (code) => resolve({ code: code ?? 0, output: out }));
  });
}

function shellEscape(s) {
  return "'" + s.replace(/'/g, "'\\''") + "'";
}

function runCmdStreaming(cmd, args, { onData, timeoutMs, signal, extraEnv, usePty } = {}) {
  return new Promise((resolve) => {
    let killedByTimeout = false;

    const env = {
      ...process.env,
      OPENCLAW_STATE_DIR: STATE_DIR,
      OPENCLAW_WORKSPACE_DIR: WORKSPACE_DIR,
      ...extraEnv,
    };

    // When usePty is true, wrap the command in `script` to provide a real PTY.
    // This is needed for CLIs that check process.stdout.isTTY (e.g. OAuth device-code flows).
    let spawnCmd = cmd;
    let spawnArgs = args;
    if (usePty) {
      const shellCmd = [cmd, ...args].map(shellEscape).join(" ");
      spawnCmd = "script";
      spawnArgs = ["-qfc", shellCmd, "/dev/null"];
    }

    const proc = childProcess.spawn(spawnCmd, spawnArgs, { env });

    let timer;
    if (timeoutMs) {
      timer = setTimeout(() => {
        killedByTimeout = true;
        try { proc.kill("SIGTERM"); } catch {}
      }, timeoutMs);
    }

    if (signal) {
      const onAbort = () => {
        try { proc.kill("SIGTERM"); } catch {}
      };
      signal.addEventListener("abort", onAbort, { once: true });
      proc.on("close", () => signal.removeEventListener("abort", onAbort));
    }

    proc.stdout?.on("data", (d) => onData?.(d.toString("utf8")));
    proc.stderr?.on("data", (d) => onData?.(d.toString("utf8")));

    proc.on("error", (err) => {
      onData?.(`\n[spawn error] ${String(err)}\n`);
      clearTimeout(timer);
      resolve({ code: 127, killedByTimeout: false });
    });

    proc.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code: code ?? (killedByTimeout ? 124 : 1), killedByTimeout });
    });
  });
}

let onboardInProgress = false;

app.post("/setup/api/run-stream", requireSetupAuth, async (req, res) => {
  if (onboardInProgress) {
    return res.status(409).json({ ok: false, error: "Setup is already running" });
  }

  try {
    if (isConfigured()) {
      await ensureGatewayRunning();
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.setHeader("X-Accel-Buffering", "no");
      res.setHeader("Cache-Control", "no-cache, no-transform");
      res.write(JSON.stringify({ type: "log", text: "Already configured.\nUse Reset setup if you want to rerun onboarding.\n" }) + "\n");
      res.write(JSON.stringify({ type: "done", ok: true }) + "\n");
      return res.end();
    }

    onboardInProgress = true;

    const ac = new AbortController();
    // Use res.on("close") — req.on("close") fires after POST body is consumed, not on disconnect
    res.on("close", () => { if (!res.writableFinished) ac.abort(); });

    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.setHeader("X-Accel-Buffering", "no");
    res.setHeader("Cache-Control", "no-cache, no-transform");

    function writeLine(obj) {
      if (!res.writableEnded) res.write(JSON.stringify(obj) + "\n");
    }

    fs.mkdirSync(STATE_DIR, { recursive: true });
    fs.mkdirSync(WORKSPACE_DIR, { recursive: true });

    const payload = req.body || {};
    const interactive = OAUTH_AUTH_CHOICES.has(payload.authChoice);

    if (interactive) {
      // --- Two-step OAuth flow ---
      // Step 1: Create base config with --auth-choice skip
      // Delete any stale config/state that might confuse the CLI
      try { fs.rmSync(configPath(), { force: true }); } catch {}
      // Also delete auth-profiles.json which may have stale state
      try { fs.rmSync(path.join(STATE_DIR, "auth-profiles.json"), { force: true }); } catch {}

      writeLine({ type: "status", step: "onboard", message: "Creating base configuration..." });
      const skipPayload = { flow: payload.flow || "quickstart", authChoice: "skip" };
      const skipArgs = buildOnboardArgs(skipPayload, { interactive: false });
      const skipFullArgs = clawArgs(skipArgs);
      const skipSafe = skipFullArgs.map((a) => a === OPENCLAW_GATEWAY_TOKEN ? a.slice(0, 8) + "..." : a);
      writeLine({ type: "log", text: `[step1] ${skipSafe.join(" ")}\n` });

      // Use runCmd (non-streaming) for reliability — this is a fast non-interactive command
      const step1 = await runCmd(OPENCLAW_NODE, skipFullArgs);
      if (step1.output) writeLine({ type: "log", text: step1.output });

      if (step1.code !== 0 || !isConfigured()) {
        const detail = step1.output?.trim() ? ` — ${step1.output.trim().slice(-300)}` : " — no output from CLI";
        writeLine({ type: "error", message: `Base config creation failed (exit code ${step1.code})${detail}` });
        onboardInProgress = false;
        return res.end();
      }
      writeLine({ type: "log", text: "Base config created successfully.\n" });

      // Step 2: OAuth login
      const useDirectDeviceCode = payload.authChoice === "openai-codex" || payload.authChoice === "codex-cli";

      if (useDirectDeviceCode) {
        // Direct OpenAI device-code flow — bypasses CLI TUI which doesn't work headlessly
        writeLine({ type: "status", step: "oauth", message: "Starting OpenAI device code flow..." });
        writeLine({ type: "log", text: "Requesting device code from OpenAI...\n" });

        try {
          const tokens = await openaiDeviceCodeFlow({
            signal: ac.signal,
            onStatus(evt) {
              if (evt.type === "device_code") {
                writeLine({ type: "log", text: `\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n` });
                writeLine({ type: "log", text: `  Open this URL in your browser:\n` });
                writeLine({ type: "log", text: `  ${evt.verificationUrl}\n\n` });
                if (evt.userCode) {
                  writeLine({ type: "log", text: `  Enter code: ${evt.userCode}\n` });
                }
                writeLine({ type: "log", text: `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n` });
                writeLine({ type: "log", text: "Waiting for you to authorize in the browser...\n" });
              } else if (evt.type === "polling") {
                // silent — just keep waiting
              } else if (evt.type === "poll_error") {
                writeLine({ type: "log", text: `[poll error] ${evt.message || `status ${evt.status}`}\n` });
              } else if (evt.type === "poll_status") {
                writeLine({ type: "log", text: `[poll] status ${evt.status}: ${evt.body}\n` });
              } else if (evt.type === "authorized") {
                writeLine({ type: "log", text: "Authorization received from OpenAI!\n" });
              }
            },
          });

          writeLine({ type: "log", text: "Authorization received! Storing credentials...\n" });

          // Write tokens to OpenClaw auth file
          const authFilePath = path.join(STATE_DIR, "auth.json");
          let authData = {};
          try { authData = JSON.parse(fs.readFileSync(authFilePath, "utf8")); } catch {}
          authData.openai = {
            type: "oauth",
            access: tokens.accessToken,
            refresh: tokens.refreshToken,
            expires: tokens.expiresAt,
          };
          fs.writeFileSync(authFilePath, JSON.stringify(authData, null, 2));
          writeLine({ type: "log", text: `Credentials saved to ${authFilePath}\n` });

          // Also write to auth-profiles.json (alternate location OpenClaw may check)
          const authProfilesPath = path.join(STATE_DIR, "auth-profiles.json");
          let profiles = {};
          try { profiles = JSON.parse(fs.readFileSync(authProfilesPath, "utf8")); } catch {}
          const profileKey = `openai-codex:default`;
          profiles[profileKey] = {
            provider: "openai-codex",
            type: "oauth",
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            expiresAt: tokens.expiresAt,
          };
          fs.writeFileSync(authProfilesPath, JSON.stringify(profiles, null, 2));
          writeLine({ type: "log", text: `Credentials also saved to ${authProfilesPath}\n` });

          // Set default model provider and agent model via config.
          // The --auth-choice skip onboard uses anthropic/claude-opus-4-6 as the default model,
          // which fails when using OpenAI Codex auth. Set the model to codex-1 (OpenAI Codex).
          await runCmd(OPENCLAW_NODE, clawArgs(["config", "set", "models.defaultProvider", "openai-codex"]));
          await runCmd(OPENCLAW_NODE, clawArgs(["config", "set", "agents.defaults.model", "codex-1"]));
          writeLine({ type: "log", text: "Default provider set to openai-codex, model set to codex-1\n" });

          // Copy auth profiles to the agent-specific directory so the gateway agent can find them.
          // The onboard --auth-choice skip doesn't create the agent auth store, so the gateway
          // looks for credentials in agents/main/agent/ and fails with "No API key found".
          const agentAuthDir = path.join(STATE_DIR, "agents", "main", "agent");
          fs.mkdirSync(agentAuthDir, { recursive: true });
          const agentAuthProfilesPath = path.join(agentAuthDir, "auth-profiles.json");
          try {
            fs.copyFileSync(authProfilesPath, agentAuthProfilesPath);
            writeLine({ type: "log", text: `Credentials copied to ${agentAuthProfilesPath}\n` });
          } catch (copyErr) {
            writeLine({ type: "log", text: `[WARNING] Could not copy auth to agent dir: ${copyErr.message}\n` });
          }
          // Also copy auth.json
          const agentAuthPath = path.join(agentAuthDir, "auth.json");
          try {
            fs.copyFileSync(authFilePath, agentAuthPath);
          } catch {};

        } catch (err) {
          writeLine({ type: "error", message: `OpenAI OAuth failed: ${err.message}` });
          onboardInProgress = false;
          return res.end();
        }
      } else {
        // Other OAuth providers — try models auth login with PTY
        writeLine({ type: "status", step: "oauth", message: `Starting ${payload.authChoice} OAuth flow...` });
        writeLine({ type: "log", text: "A device code URL should appear below. Open it in your browser to authorize.\n" });

        let authOutput = "";
        const authResult = await runCmdStreaming(OPENCLAW_NODE, clawArgs([
          "models", "auth", "login",
          "--provider", payload.authChoice,
          "--set-default",
        ]), {
          timeoutMs: 180_000,
          signal: ac.signal,
          usePty: true,
          extraEnv: { TERM: "xterm-256color", COLUMNS: "120", LINES: "40" },
          onData(chunk) {
            authOutput += chunk;
            const clean = chunk.replace(/\x1b\[[0-9;]*[a-zA-Z]|\x1b\[\?[0-9;]*[a-zA-Z]/g, "").trim();
            if (clean) writeLine({ type: "log", text: clean + "\n" });
          },
        });

        if (authResult.killedByTimeout) {
          writeLine({ type: "error", message: "OAuth timed out after 3 minutes. Please try again and complete the browser login faster." });
          onboardInProgress = false;
          return res.end();
        }

        if (authResult.code !== 0) {
          const detail = authOutput.trim() ? ` — ${authOutput.replace(/\x1b\[[0-9;?]*[a-zA-Z]/g, "").trim().slice(-300)}` : "";
          writeLine({ type: "error", message: `OAuth login failed (exit code ${authResult.code})${detail}` });
          onboardInProgress = false;
          return res.end();
        }
      }

      writeLine({ type: "log", text: "OAuth login completed successfully.\n" });
    } else {
      // --- Standard non-interactive flow ---
      const onboardArgs = buildOnboardArgs(payload, { interactive: false });
      const timeoutMs = 60_000;

      writeLine({ type: "status", step: "onboard", message: "Running onboard..." });

      let capturedOutput = "";
      const onboard = await runCmdStreaming(OPENCLAW_NODE, clawArgs(onboardArgs), {
        timeoutMs,
        signal: ac.signal,
        onData(chunk) {
          capturedOutput += chunk;
          writeLine({ type: "log", text: chunk });
        },
      });

      if (onboard.killedByTimeout) {
        writeLine({ type: "error", message: "Onboard timed out." });
        onboardInProgress = false;
        return res.end();
      }

      const ok = onboard.code === 0 && isConfigured();
      if (!ok) {
        const detail = capturedOutput.trim() ? ` — ${capturedOutput.trim().slice(-200)}` : " — no output from CLI";
        writeLine({ type: "error", message: `Onboard failed (exit code ${onboard.code})${detail}` });
        onboardInProgress = false;
        return res.end();
      }
    }

    // Post-onboard steps (same as /setup/api/run)
    writeLine({ type: "status", step: "token-sync", message: "Syncing gateway token..." });

    await runCmd(OPENCLAW_NODE, clawArgs(["config", "set", "gateway.mode", "local"]));
    await runCmd(OPENCLAW_NODE, clawArgs(["config", "set", "gateway.auth.mode", "token"]));
    const setTokenResult = await runCmd(OPENCLAW_NODE, clawArgs(["config", "set", "gateway.auth.token", OPENCLAW_GATEWAY_TOKEN]));
    if (setTokenResult.code !== 0) {
      writeLine({ type: "log", text: `[WARNING] Failed to set gateway token: ${setTokenResult.output}\n` });
    } else {
      writeLine({ type: "log", text: "[token-sync] Gateway token synced successfully\n" });
    }

    writeLine({ type: "status", step: "config", message: "Applying gateway config..." });

    await runCmd(OPENCLAW_NODE, clawArgs(["config", "set", "gateway.bind", "loopback"]));
    await runCmd(OPENCLAW_NODE, clawArgs(["config", "set", "gateway.port", String(INTERNAL_GATEWAY_PORT)]));
    await runCmd(OPENCLAW_NODE, clawArgs(["config", "set", "--json", "gateway.controlUi.allowInsecureAuth", "true"]));
    await runCmd(OPENCLAW_NODE, clawArgs(["config", "set", "--json", "gateway.controlUi.dangerouslyDisableDeviceAuth", "true"]));
    // Grant full operator scopes to insecure auth (needed for Control UI chat to work)
    await runCmd(OPENCLAW_NODE, clawArgs(["config", "set", "--json", "gateway.controlUi.insecureScopes", '["operator.admin","operator.read","operator.write","operator.approvals","operator.pairing"]']));
    await runCmd(OPENCLAW_NODE, clawArgs(["config", "set", "--json", "gateway.trustedProxies", '["127.0.0.1","::1"]']));

    // OpenRouter fallback
    if (payload.authChoice === "openrouter-api-key") {
      const orResult = await runCmd(OPENCLAW_NODE, clawArgs(["config", "set", "--json", "models.providers.openrouter", JSON.stringify({ baseUrl: "https://openrouter.ai/api/v1", api: "openai" })]));
      writeLine({ type: "log", text: `[openrouter-fallback] exit=${orResult.code}\n` });
    }

    // Sub-agent model
    if (payload.subagentModel?.trim()) {
      const saResult = await runCmd(OPENCLAW_NODE, clawArgs(["config", "set", "agents.defaults.subagents.model", payload.subagentModel.trim()]));
      writeLine({ type: "log", text: `[subagent-model] exit=${saResult.code}\n` });
    }

    // Channel setup
    writeLine({ type: "status", step: "channels", message: "Configuring channels..." });

    const channelsHelp = await runCmd(OPENCLAW_NODE, clawArgs(["channels", "add", "--help"]));
    const helpText = channelsHelp.output || "";
    const supports = (name) => helpText.includes(name);

    if (payload.telegramToken?.trim()) {
      if (!supports("telegram")) {
        writeLine({ type: "log", text: "[telegram] skipped (unsupported in this build)\n" });
      } else {
        const cfgObj = { enabled: true, dmPolicy: "pairing", botToken: payload.telegramToken.trim(), groupPolicy: "allowlist", streamMode: "partial" };
        const set = await runCmd(OPENCLAW_NODE, clawArgs(["config", "set", "--json", "channels.telegram", JSON.stringify(cfgObj)]));
        writeLine({ type: "log", text: `[telegram config] exit=${set.code}\n` });
      }
    }

    if (payload.discordToken?.trim()) {
      if (!supports("discord")) {
        writeLine({ type: "log", text: "[discord] skipped (unsupported in this build)\n" });
      } else {
        const cfgObj = { enabled: true, token: payload.discordToken.trim(), groupPolicy: "allowlist", dm: { policy: "pairing" } };
        const set = await runCmd(OPENCLAW_NODE, clawArgs(["config", "set", "--json", "channels.discord", JSON.stringify(cfgObj)]));
        writeLine({ type: "log", text: `[discord config] exit=${set.code}\n` });
      }
    }

    if (payload.slackBotToken?.trim() || payload.slackAppToken?.trim()) {
      if (!supports("slack")) {
        writeLine({ type: "log", text: "[slack] skipped (unsupported in this build)\n" });
      } else {
        const cfgObj = { enabled: true, botToken: payload.slackBotToken?.trim() || undefined, appToken: payload.slackAppToken?.trim() || undefined };
        const set = await runCmd(OPENCLAW_NODE, clawArgs(["config", "set", "--json", "channels.slack", JSON.stringify(cfgObj)]));
        writeLine({ type: "log", text: `[slack config] exit=${set.code}\n` });
      }
    }

    // Restart gateway
    writeLine({ type: "status", step: "gateway", message: "Starting gateway..." });
    await restartGateway();

    writeLine({ type: "done", ok: true });
    onboardInProgress = false;
    res.end();
  } catch (err) {
    console.error("[/setup/api/run-stream] error:", err);
    if (!res.headersSent) {
      return res.status(500).json({ ok: false, error: String(err) });
    }
    try {
      res.write(JSON.stringify({ type: "error", message: String(err) }) + "\n");
    } catch {}
    onboardInProgress = false;
    res.end();
  }
});

app.post("/setup/api/run", requireSetupAuth, async (req, res) => {
  try {
    if (isConfigured()) {
      await ensureGatewayRunning();
      return res.json({
        ok: true,
        output:
          "Already configured.\nUse Reset setup if you want to rerun onboarding.\n",
      });
    }

    fs.mkdirSync(STATE_DIR, { recursive: true });
    fs.mkdirSync(WORKSPACE_DIR, { recursive: true });

    const payload = req.body || {};
    const onboardArgs = buildOnboardArgs(payload, { interactive: false });

    // DIAGNOSTIC: Log token we're passing to onboard
    console.log(`[onboard] ========== TOKEN DIAGNOSTIC START ==========`);
    console.log(`[onboard] Wrapper token (from env/file/generated): ${OPENCLAW_GATEWAY_TOKEN.slice(0, 16)}... (length: ${OPENCLAW_GATEWAY_TOKEN.length})`);
    console.log(`[onboard] Onboard command args include: --gateway-token ${OPENCLAW_GATEWAY_TOKEN.slice(0, 16)}...`);
    console.log(`[onboard] Full onboard command: node ${clawArgs(onboardArgs).join(' ').replace(OPENCLAW_GATEWAY_TOKEN, OPENCLAW_GATEWAY_TOKEN.slice(0, 16) + '...')}`);

    const onboard = await runCmd(OPENCLAW_NODE, clawArgs(onboardArgs));

    let extra = "";

    const ok = onboard.code === 0 && isConfigured();

    // DIAGNOSTIC: Check what token onboard actually wrote to config
    if (ok) {
      try {
        const configAfterOnboard = JSON.parse(fs.readFileSync(configPath(), "utf8"));
        const tokenAfterOnboard = configAfterOnboard?.gateway?.auth?.token;
        console.log(`[onboard] Token in config AFTER onboard: ${tokenAfterOnboard?.slice(0, 16)}... (length: ${tokenAfterOnboard?.length || 0})`);
        console.log(`[onboard] Token match: ${tokenAfterOnboard === OPENCLAW_GATEWAY_TOKEN ? '✓ MATCHES' : '✗ MISMATCH!'}`);
        if (tokenAfterOnboard !== OPENCLAW_GATEWAY_TOKEN) {
          console.log(`[onboard] ⚠️  PROBLEM: onboard command ignored --gateway-token flag and wrote its own token!`);
          extra += `\n[WARNING] onboard wrote different token than expected\n`;
          extra += `  Expected: ${OPENCLAW_GATEWAY_TOKEN.slice(0, 16)}...\n`;
          extra += `  Got:      ${tokenAfterOnboard?.slice(0, 16)}...\n`;
        }
      } catch (err) {
        console.error(`[onboard] Could not check config after onboard: ${err}`);
      }
    }

    // Optional channel setup (only after successful onboarding, and only if the installed CLI supports it).
    if (ok) {
      // Ensure gateway token is written into config so the browser UI can authenticate reliably.
      // (We also enforce loopback bind since the wrapper proxies externally.)
      console.log(`[onboard] Now syncing wrapper token to config (${OPENCLAW_GATEWAY_TOKEN.slice(0, 8)}...)`);

      await runCmd(OPENCLAW_NODE, clawArgs(["config", "set", "gateway.mode", "local"]));
      await runCmd(
        OPENCLAW_NODE,
        clawArgs(["config", "set", "gateway.auth.mode", "token"]),
      );

      const setTokenResult = await runCmd(
        OPENCLAW_NODE,
        clawArgs([
          "config",
          "set",
          "gateway.auth.token",
          OPENCLAW_GATEWAY_TOKEN,
        ]),
      );

      console.log(`[onboard] config set gateway.auth.token result: exit code ${setTokenResult.code}`);
      if (setTokenResult.output?.trim()) {
        console.log(`[onboard] config set output: ${setTokenResult.output}`);
      }

      if (setTokenResult.code !== 0) {
        console.error(`[onboard] ⚠️  WARNING: config set gateway.auth.token failed with code ${setTokenResult.code}`);
        extra += `\n[WARNING] Failed to set gateway token in config: ${setTokenResult.output}\n`;
      }

      // Verify the token was actually written to config
      try {
        const configContent = fs.readFileSync(configPath(), "utf8");
        const config = JSON.parse(configContent);
        const configToken = config?.gateway?.auth?.token;

        console.log(`[onboard] Token verification after sync:`);
        console.log(`[onboard]   Wrapper token: ${OPENCLAW_GATEWAY_TOKEN.slice(0, 16)}... (len: ${OPENCLAW_GATEWAY_TOKEN.length})`);
        console.log(`[onboard]   Config token:  ${configToken?.slice(0, 16)}... (len: ${configToken?.length || 0})`);

        if (configToken !== OPENCLAW_GATEWAY_TOKEN) {
          console.error(`[onboard] ✗ ERROR: Token mismatch after config set!`);
          console.error(`[onboard]   Full wrapper token: ${OPENCLAW_GATEWAY_TOKEN}`);
          console.error(`[onboard]   Full config token:  ${configToken || 'null'}`);
          extra += `\n[ERROR] Token verification failed! Config has different token than wrapper.\n`;
          extra += `  Wrapper: ${OPENCLAW_GATEWAY_TOKEN.slice(0, 16)}...\n`;
          extra += `  Config:  ${configToken?.slice(0, 16)}...\n`;
        } else {
          console.log(`[onboard] ✓ Token verification PASSED - tokens match!`);
          extra += `\n[onboard] ✓ Gateway token synced successfully\n`;
        }
      } catch (err) {
        console.error(`[onboard] ERROR: Could not verify token in config: ${err}`);
        extra += `\n[ERROR] Could not verify token: ${String(err)}\n`;
      }

      console.log(`[onboard] ========== TOKEN DIAGNOSTIC END ==========`);

      await runCmd(
        OPENCLAW_NODE,
        clawArgs(["config", "set", "gateway.bind", "loopback"]),
      );
      await runCmd(
        OPENCLAW_NODE,
        clawArgs([
          "config",
          "set",
          "gateway.port",
          String(INTERNAL_GATEWAY_PORT),
        ]),
      );
      // Allow Control UI access without device pairing (fixes error 1008: pairing required)
      await runCmd(
        OPENCLAW_NODE,
        clawArgs(["config", "set", "--json", "gateway.controlUi.allowInsecureAuth", "true"]),
      );
      // Disable device auth for behind-proxy scenarios (GitHub issue #1690)
      await runCmd(
        OPENCLAW_NODE,
        clawArgs(["config", "set", "--json", "gateway.controlUi.dangerouslyDisableDeviceAuth", "true"]),
      );
      // Grant full operator scopes to insecure auth (fixes "missing scope: operator.write")
      await runCmd(
        OPENCLAW_NODE,
        clawArgs(["config", "set", "--json", "gateway.controlUi.insecureScopes", '["operator.admin","operator.read","operator.write","operator.approvals","operator.pairing"]']),
      );

      // Trust the loopback proxy so X-Forwarded-* headers are honoured
      await runCmd(
        OPENCLAW_NODE,
        clawArgs(["config", "set", "--json", "gateway.trustedProxies", '["127.0.0.1","::1"]']),
      );

      // Register OpenRouter as a custom provider so uncatalogued models
      // (e.g., openrouter/pony-alpha) can resolve via resolveModel()'s
      // generic provider-config fallback.  Without this entry, any OpenRouter
      // model not in the built-in models.generated catalog triggers
      // "Unknown model" errors.  This is harmless if OpenRouter is unused.
      if (payload.authChoice === "openrouter-api-key") {
        const orResult = await runCmd(
          OPENCLAW_NODE,
          clawArgs([
            "config",
            "set",
            "--json",
            "models.providers.openrouter",
            JSON.stringify({
              baseUrl: "https://openrouter.ai/api/v1",
              api: "openai",
            }),
          ]),
        );
        extra += `\n[openrouter-fallback] exit=${orResult.code}\n${orResult.output || "(ok)"}\n`;
      }

      // Configure sub-agent model if specified by the user
      if (payload.subagentModel?.trim()) {
        const saResult = await runCmd(
          OPENCLAW_NODE,
          clawArgs([
            "config",
            "set",
            "agents.defaults.subagents.model",
            payload.subagentModel.trim(),
          ]),
        );
        extra += `\n[subagent-model] exit=${saResult.code}\n${saResult.output || "(ok)"}\n`;
      }

      const channelsHelp = await runCmd(
        OPENCLAW_NODE,
        clawArgs(["channels", "add", "--help"]),
      );
      const helpText = channelsHelp.output || "";

      const supports = (name) => helpText.includes(name);

      if (payload.telegramToken?.trim()) {
        if (!supports("telegram")) {
          extra +=
            "\n[telegram] skipped (this openclaw build does not list telegram in `channels add --help`)\n";
        } else {
          // Avoid `channels add` here (it has proven flaky across builds); write config directly.
          const token = payload.telegramToken.trim();
          const cfgObj = {
            enabled: true,
            dmPolicy: "pairing",
            botToken: token,
            groupPolicy: "allowlist",
            streamMode: "partial",
          };
          const set = await runCmd(
            OPENCLAW_NODE,
            clawArgs([
              "config",
              "set",
              "--json",
              "channels.telegram",
              JSON.stringify(cfgObj),
            ]),
          );
          const get = await runCmd(
            OPENCLAW_NODE,
            clawArgs(["config", "get", "channels.telegram"]),
          );
          extra += `\n[telegram config] exit=${set.code} (output ${set.output.length} chars)\n${set.output || "(no output)"}`;
          extra += `\n[telegram verify] exit=${get.code} (output ${get.output.length} chars)\n${get.output || "(no output)"}`;
        }
      }

      if (payload.discordToken?.trim()) {
        if (!supports("discord")) {
          extra +=
            "\n[discord] skipped (this openclaw build does not list discord in `channels add --help`)\n";
        } else {
          const token = payload.discordToken.trim();
          const cfgObj = {
            enabled: true,
            token,
            groupPolicy: "allowlist",
            dm: {
              policy: "pairing",
            },
          };
          const set = await runCmd(
            OPENCLAW_NODE,
            clawArgs([
              "config",
              "set",
              "--json",
              "channels.discord",
              JSON.stringify(cfgObj),
            ]),
          );
          const get = await runCmd(
            OPENCLAW_NODE,
            clawArgs(["config", "get", "channels.discord"]),
          );
          extra += `\n[discord config] exit=${set.code} (output ${set.output.length} chars)\n${set.output || "(no output)"}`;
          extra += `\n[discord verify] exit=${get.code} (output ${get.output.length} chars)\n${get.output || "(no output)"}`;
        }
      }

      if (payload.slackBotToken?.trim() || payload.slackAppToken?.trim()) {
        if (!supports("slack")) {
          extra +=
            "\n[slack] skipped (this openclaw build does not list slack in `channels add --help`)\n";
        } else {
          const cfgObj = {
            enabled: true,
            botToken: payload.slackBotToken?.trim() || undefined,
            appToken: payload.slackAppToken?.trim() || undefined,
          };
          const set = await runCmd(
            OPENCLAW_NODE,
            clawArgs([
              "config",
              "set",
              "--json",
              "channels.slack",
              JSON.stringify(cfgObj),
            ]),
          );
          const get = await runCmd(
            OPENCLAW_NODE,
            clawArgs(["config", "get", "channels.slack"]),
          );
          extra += `\n[slack config] exit=${set.code} (output ${set.output.length} chars)\n${set.output || "(no output)"}`;
          extra += `\n[slack verify] exit=${get.code} (output ${get.output.length} chars)\n${get.output || "(no output)"}`;
        }
      }

      // Apply changes immediately.
      await restartGateway();
    }

    return res.status(ok ? 200 : 500).json({
      ok,
      output: `${onboard.output}${extra}`,
    });
  } catch (err) {
    console.error("[/setup/api/run] error:", err);
    return res
      .status(500)
      .json({ ok: false, output: `Internal error: ${String(err)}` });
  }
});

app.get("/setup/api/debug", requireSetupAuth, async (_req, res) => {
  const v = await runCmd(OPENCLAW_NODE, clawArgs(["--version"]));
  const help = await runCmd(
    OPENCLAW_NODE,
    clawArgs(["channels", "add", "--help"]),
  );
  // Read config for debugging
  let config = null;
  try { config = JSON.parse(fs.readFileSync(configPath(), "utf8")); } catch {}

  // Search gateway source for agent model config
  let agentModelGrep = null;
  try {
    const { execSync } = childProcess;
    agentModelGrep = execSync(`sed -n '17100,17120p' /openclaw/dist/gateway-cli-DO7TBq1j.js 2>/dev/null`, { encoding: "utf8", timeout: 5000 }).trim();
  } catch {}

  res.json({
    wrapper: {
      node: process.version,
      port: PORT,
      stateDir: STATE_DIR,
      workspaceDir: WORKSPACE_DIR,
      configPath: configPath(),
      gatewayTokenFromEnv: Boolean(process.env.OPENCLAW_GATEWAY_TOKEN?.trim()),
      gatewayTokenPersisted: fs.existsSync(
        path.join(STATE_DIR, "gateway.token"),
      ),
      railwayCommit: process.env.RAILWAY_GIT_COMMIT_SHA || null,
    },
    openclaw: {
      entry: OPENCLAW_ENTRY,
      node: OPENCLAW_NODE,
      version: v.output.trim(),
      channelsAddHelpIncludesTelegram: help.output.includes("telegram"),
    },
    gatewayConfig: config?.gateway || null,
    agentsConfig: config?.agents || null,
    modelsConfig: config?.models || null,
    agentModelGrep,
    fullConfigKeys: config ? Object.keys(config) : null,
  });
});

app.post("/setup/api/pairing/approve", requireSetupAuth, async (req, res) => {
  const { channel, code } = req.body || {};
  if (!channel || !code) {
    return res
      .status(400)
      .json({ ok: false, error: "Missing channel or code" });
  }
  const r = await runCmd(
    OPENCLAW_NODE,
    clawArgs(["pairing", "approve", String(channel), String(code)]),
  );
  return res
    .status(r.code === 0 ? 200 : 500)
    .json({ ok: r.code === 0, output: r.output });
});

app.post("/setup/api/reset", requireSetupAuth, async (_req, res) => {
  // Minimal reset: delete the config file so /setup can rerun.
  // Keep credentials/sessions/workspace by default.
  // Also clear the in-progress flag in case a previous run got stuck.
  onboardInProgress = false;
  try {
    fs.rmSync(configPath(), { force: true });
    res
      .type("text/plain")
      .send("OK - deleted config file and cleared in-progress flag. You can rerun setup now.");
  } catch (err) {
    res.status(500).type("text/plain").send(String(err));
  }
});

// ---------------------------------------------------------------------------
// Model configuration — update sub-agent model + OpenRouter fallback
// on an already-configured instance without re-running onboarding.
// ---------------------------------------------------------------------------
app.post("/setup/api/update-models", requireSetupAuth, async (req, res) => {
  if (!isConfigured()) {
    return res
      .status(400)
      .json({ ok: false, error: "Not configured yet. Run setup first." });
  }

  const payload = req.body || {};
  let output = "";

  // Enable OpenRouter uncatalogued-model fallback so models not in the
  // built-in catalog (e.g., openrouter/pony-alpha) resolve correctly.
  if (payload.enableOpenRouterFallback) {
    const r = await runCmd(
      OPENCLAW_NODE,
      clawArgs([
        "config",
        "set",
        "--json",
        "models.providers.openrouter",
        JSON.stringify({
          baseUrl: "https://openrouter.ai/api/v1",
          api: "openai",
        }),
      ]),
    );
    output += `[openrouter-fallback] exit=${r.code}\n${r.output || "(ok)"}\n`;
  }

  // Update main agent model
  if (payload.agentModel?.trim()) {
    const r = await runCmd(
      OPENCLAW_NODE,
      clawArgs([
        "config",
        "set",
        "agents.defaults.model",
        payload.agentModel.trim(),
      ]),
    );
    output += `[agent-model] set to ${payload.agentModel.trim()} — exit=${r.code}\n${r.output || "(ok)"}\n`;
  }

  // Update sub-agent model
  if (payload.subagentModel?.trim()) {
    const r = await runCmd(
      OPENCLAW_NODE,
      clawArgs([
        "config",
        "set",
        "agents.defaults.subagents.model",
        payload.subagentModel.trim(),
      ]),
    );
    output += `[subagent-model] set to ${payload.subagentModel.trim()} — exit=${r.code}\n${r.output || "(ok)"}\n`;
  }

  // Restart gateway to apply changes
  try {
    await restartGateway();
    output += "[gateway] restarted to apply model config\n";
  } catch (err) {
    output += `[gateway] restart error: ${String(err)}\n`;
  }

  return res.json({ ok: true, output });
});

app.get("/setup/export", requireSetupAuth, async (_req, res) => {
  fs.mkdirSync(STATE_DIR, { recursive: true });
  fs.mkdirSync(WORKSPACE_DIR, { recursive: true });

  res.setHeader("content-type", "application/gzip");
  res.setHeader(
    "content-disposition",
    `attachment; filename="openclaw-backup-${new Date().toISOString().replace(/[:.]/g, "-")}.tar.gz"`,
  );

  // Prefer exporting from a common /data root so archives are easy to inspect and restore.
  // This preserves dotfiles like /data/.openclaw/openclaw.json.
  const stateAbs = path.resolve(STATE_DIR);
  const workspaceAbs = path.resolve(WORKSPACE_DIR);

  const dataRoot = "/data";
  const underData = (p) => p === dataRoot || p.startsWith(dataRoot + path.sep);

  let cwd = "/";
  let paths = [stateAbs, workspaceAbs].map((p) => p.replace(/^\//, ""));

  if (underData(stateAbs) && underData(workspaceAbs)) {
    cwd = dataRoot;
    // We export relative to /data so the archive contains: .openclaw/... and workspace/...
    paths = [
      path.relative(dataRoot, stateAbs) || ".",
      path.relative(dataRoot, workspaceAbs) || ".",
    ];
  }

  const stream = tar.c(
    {
      gzip: true,
      portable: true,
      noMtime: true,
      cwd,
      onwarn: () => {},
    },
    paths,
  );

  stream.on("error", (err) => {
    console.error("[export]", err);
    if (!res.headersSent) res.status(500);
    res.end(String(err));
  });

  stream.pipe(res);
});

// ---------------------------------------------------------------------------
// File API — list, read, write workspace files (protected by SETUP_PASSWORD)
// ---------------------------------------------------------------------------

function safePath(userPath) {
  const resolved = path.resolve(WORKSPACE_DIR, userPath || "");
  if (!resolved.startsWith(path.resolve(WORKSPACE_DIR))) return null;
  return resolved;
}

app.get("/setup/api/files/list", requireSetupAuth, (req, res) => {
  const target = safePath(req.query.path || "");
  if (!target) return res.status(400).json({ error: "Invalid path" });

  try {
    const entries = fs.readdirSync(target, { withFileTypes: true });
    const items = entries.map((e) => ({
      name: e.name,
      type: e.isDirectory() ? "dir" : "file",
    }));
    res.json({ path: path.relative(WORKSPACE_DIR, target) || ".", items });
  } catch (err) {
    res.status(err.code === "ENOENT" ? 404 : 500).json({ error: String(err) });
  }
});

app.get("/setup/api/files/read", requireSetupAuth, (req, res) => {
  const target = safePath(req.query.path || "");
  if (!target) return res.status(400).json({ error: "Invalid path" });

  try {
    const stat = fs.statSync(target);
    if (stat.isDirectory()) {
      return res.status(400).json({ error: "Path is a directory, use /list" });
    }
    const content = fs.readFileSync(target, "utf8");
    res.json({
      path: path.relative(WORKSPACE_DIR, target),
      size: stat.size,
      content,
    });
  } catch (err) {
    res.status(err.code === "ENOENT" ? 404 : 500).json({ error: String(err) });
  }
});

app.post("/setup/api/files/write", requireSetupAuth, (req, res) => {
  const { path: filePath, content } = req.body || {};
  if (!filePath) return res.status(400).json({ error: "Missing path" });
  if (typeof content !== "string") {
    return res.status(400).json({ error: "Missing or invalid content" });
  }

  const target = safePath(filePath);
  if (!target) return res.status(400).json({ error: "Invalid path" });

  try {
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, content, "utf8");
    res.json({
      ok: true,
      path: path.relative(WORKSPACE_DIR, target),
      size: Buffer.byteLength(content, "utf8"),
    });
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

app.delete("/setup/api/files/delete", requireSetupAuth, (req, res) => {
  const target = safePath(req.query.path || "");
  if (!target) return res.status(400).json({ error: "Invalid path" });
  if (target === path.resolve(WORKSPACE_DIR)) {
    return res.status(400).json({ error: "Cannot delete workspace root" });
  }

  try {
    fs.rmSync(target, { recursive: true, force: true });
    res.json({ ok: true, path: path.relative(WORKSPACE_DIR, target) });
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

// Proxy everything else to the gateway.
const proxy = httpProxy.createProxyServer({
  target: GATEWAY_TARGET,
  ws: true,
  xfwd: true,
});

proxy.on("error", (err, _req, _res) => {
  console.error("[proxy]", err);
});

// Inject auth token into HTTP proxy requests
proxy.on("proxyReq", (proxyReq, req, res) => {
  console.log(`[proxy] HTTP ${req.method} ${req.url} - injecting token: ${OPENCLAW_GATEWAY_TOKEN.slice(0, 16)}...`);
  proxyReq.setHeader("Authorization", `Bearer ${OPENCLAW_GATEWAY_TOKEN}`);
});

// Inject auth token into WebSocket proxy requests and strip forwarded-client
// headers so the gateway sees the connection as local (127.0.0.1).
// With allowInsecureAuth the gateway skips token auth for local clients.
proxy.on("proxyReqWs", (proxyReq, req, socket, options, head) => {
  proxyReq.setHeader("Authorization", `Bearer ${OPENCLAW_GATEWAY_TOKEN}`);
  proxyReq.removeHeader("x-forwarded-for");
  proxyReq.removeHeader("x-forwarded-proto");
  proxyReq.removeHeader("x-forwarded-host");
  proxyReq.removeHeader("x-forwarded-port");
  proxyReq.removeHeader("x-real-ip");
});

app.use(async (req, res) => {
  // If not configured, force users to /setup for any non-setup routes.
  if (!isConfigured() && !req.path.startsWith("/setup")) {
    return res.redirect("/setup");
  }

  if (isConfigured()) {
    try {
      await ensureGatewayRunning();
    } catch (err) {
      return res
        .status(503)
        .type("text/plain")
        .send(`Gateway not ready: ${String(err)}`);
    }
  }

  // Redirect browser requests to a tokenized URL so the Control UI can
  // include the gateway token in its WS connect frames.
  if (
    !req.query.token &&
    req.accepts("html") &&
    (req.path === "/" || req.path.startsWith("/openclaw"))
  ) {
    const sep = req.url.includes("?") ? "&" : "?";
    return res.redirect(`${req.url}${sep}token=${OPENCLAW_GATEWAY_TOKEN}`);
  }

  // Proxy to gateway (auth token injected via proxyReq event)
  return proxy.web(req, res, { target: GATEWAY_TARGET });
});

// Create HTTP server from Express app
const server = app.listen(PORT, () => {
  console.log(`[wrapper] listening on port ${PORT}`);
  console.log(`[wrapper] setup wizard: http://localhost:${PORT}/setup`);
  console.log(`[wrapper] configured: ${isConfigured()}`);
});

// Handle WebSocket upgrades
server.on("upgrade", async (req, socket, head) => {
  if (!isConfigured()) {
    socket.destroy();
    return;
  }
  try {
    await ensureGatewayRunning();
  } catch {
    socket.destroy();
    return;
  }

  // Inject auth token via headers option (req.headers modification doesn't work for WS)
  console.log(`[ws-upgrade] Proxying WebSocket upgrade with token: ${OPENCLAW_GATEWAY_TOKEN.slice(0, 16)}...`);

  proxy.ws(req, socket, head, {
    target: GATEWAY_TARGET,
    headers: {
      Authorization: `Bearer ${OPENCLAW_GATEWAY_TOKEN}`,
    },
  });
});

process.on("SIGTERM", () => {
  // Best-effort shutdown
  try {
    if (gatewayProc) gatewayProc.kill("SIGTERM");
  } catch {
    // ignore
  }
  process.exit(0);
});
