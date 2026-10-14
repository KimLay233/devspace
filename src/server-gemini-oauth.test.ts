import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadConfig } from "./config.js";
import { createServer } from "./server.js";
import { writeTestDevspaceConfig } from "./test-support/config.test.js";

test("Gemini Web OAuth authorization flow with static client ID and Secret", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-gemini-oauth-"));
  const publicBaseUrl = "https://agent.example.com";
  const geminiRedirectUri = "https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-100729754097216200767-bbb_080909_site";
  const clientId = "https://bbb.080909.site/mcp";
  const clientSecret = "my-test-secret-123456";
  const ownerToken = "test-owner-token-that-is-long-enough";

  const config = loadConfig(writeTestDevspaceConfig(join(root, "config"), {
    server: { publicBaseUrl },
    storage: { stateDir: join(root, "state") },
    workspaces: { allowedRoots: [root] },
    oauth: {
      staticClients: [
        {
          clientId,
          clientSecret,
          clientName: "Gemini Web",
          redirectUris: [geminiRedirectUri],
        },
      ],
    },
    logging: { level: "silent" },
  }));

  const running = createServer(config);
  const listener = running.app.listen(0, "127.0.0.1");

  t.after(async () => {
    await running.close();
    listener.closeAllConnections();
    await new Promise<void>((resolve, reject) => listener.close((error) => error ? reject(error) : resolve()));
    await rm(root, { recursive: true, force: true });
  });

  await once(listener, "listening");
  const address = listener.address();
  assert.ok(address && typeof address !== "string");
  const serverBase = `http://127.0.0.1:${address.port}`;

  // 1. Discovery: Check /.well-known/oauth-authorization-server
  const metaRes = await fetch(`${serverBase}/.well-known/oauth-authorization-server`);
  assert.equal(metaRes.status, 200);
  const meta = await metaRes.json() as { authorization_endpoint: string; token_endpoint: string };
  assert.equal(meta.authorization_endpoint, `${publicBaseUrl}/authorize`);
  assert.equal(meta.token_endpoint, `${publicBaseUrl}/token`);

  // 2. PKCE setup
  const codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url");

  // 3. Initiate GET /authorize without resource parameter (standard OAuth client / Gemini flow)
  const authUrl = new URL(`${serverBase}/authorize`);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", clientId);
  authUrl.searchParams.set("redirect_uri", geminiRedirectUri);
  authUrl.searchParams.set("code_challenge", codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");
  authUrl.searchParams.set("state", "gemini-state-xyz");

  const getAuthRes = await fetch(authUrl.href);
  assert.equal(getAuthRes.status, 200);
  const getAuthHtml = await getAuthRes.text();
  assert.match(getAuthHtml, /Owner password/);

  // 4. Submit POST /authorize with owner password
  const postAuthRes = await fetch(`${serverBase}/authorize`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: geminiRedirectUri,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      state: "gemini-state-xyz",
      owner_token: ownerToken,
    }).toString(),
    redirect: "manual",
  });

  assert.equal(postAuthRes.status, 302);
  const redirectLocation = postAuthRes.headers.get("location");
  assert.ok(redirectLocation);
  assert.ok(redirectLocation.startsWith(geminiRedirectUri));

  const redirectedUrl = new URL(redirectLocation);
  const authCode = redirectedUrl.searchParams.get("code");
  assert.ok(authCode);
  assert.equal(redirectedUrl.searchParams.get("state"), "gemini-state-xyz");

  // 5. Test invalid client_secret rejection
  const badTokenRes = await fetch(`${serverBase}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: authCode,
      code_verifier: codeVerifier,
      client_id: clientId,
      client_secret: "wrong-secret",
      redirect_uri: geminiRedirectUri,
    }).toString(),
  });
  assert.equal(badTokenRes.status, 400);

  // 6. Exchange authorization code with correct client_secret
  const tokenRes = await fetch(`${serverBase}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: authCode,
      code_verifier: codeVerifier,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: geminiRedirectUri,
    }).toString(),
  });

  assert.equal(tokenRes.status, 200);
  const tokenData = await tokenRes.json() as {
    access_token: string;
    token_type: string;
    refresh_token: string;
  };
  assert.ok(tokenData.access_token);
  assert.equal(tokenData.token_type.toLowerCase(), "bearer");
  assert.ok(tokenData.refresh_token);

  // 7. Call MCP endpoint with the obtained Access Token
  const mcpRes = await fetch(`${serverBase}/mcp`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${tokenData.access_token}`,
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-03-26",
        capabilities: {},
        clientInfo: { name: "gemini-web", version: "1.0.0" },
      },
    }),
  });

  assert.equal(mcpRes.status, 200);
  const mcpBody = await mcpRes.text();
  assert.match(mcpBody, /"serverInfo"/);
});

test("Gemini Web dynamically accepts allowedRedirectHosts without pre-configuring exact redirect URI", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-gemini-dynamic-"));
  const publicBaseUrl = "https://agent.example.com";
  // Subdomain / path changed, but host is still *.googleusercontent.com
  const dynamicRedirectUri = "https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-999999-another_account";
  const clientId = "gemini-dynamic-client";
  const clientSecret = "dynamic-secret";
  const ownerToken = "test-owner-token-that-is-long-enough";

  const config = loadConfig(writeTestDevspaceConfig(join(root, "config"), {
    server: { publicBaseUrl },
    storage: { stateDir: join(root, "state") },
    workspaces: { allowedRoots: [root] },
    oauth: {
      staticClients: [
        {
          clientId,
          clientSecret,
          // Notice: redirectUris is initially EMPTY!
          redirectUris: [],
        },
      ],
    },
    logging: { level: "silent" },
  }));

  const running = createServer(config);
  const listener = running.app.listen(0, "127.0.0.1");

  t.after(async () => {
    await running.close();
    listener.closeAllConnections();
    await new Promise<void>((resolve, reject) => listener.close((error) => error ? reject(error) : resolve()));
    await rm(root, { recursive: true, force: true });
  });

  await once(listener, "listening");
  const address = listener.address();
  assert.ok(address && typeof address !== "string");
  const serverBase = `http://127.0.0.1:${address.port}`;

  const codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url");

  // Initiate GET /authorize with the dynamic redirect URI
  const authUrl = new URL(`${serverBase}/authorize`);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", clientId);
  authUrl.searchParams.set("redirect_uri", dynamicRedirectUri);
  authUrl.searchParams.set("code_challenge", codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  const getAuthRes = await fetch(authUrl.href);
  assert.equal(getAuthRes.status, 200);

  // Submit approval
  const postAuthRes = await fetch(`${serverBase}/authorize`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: dynamicRedirectUri,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      owner_token: ownerToken,
    }).toString(),
    redirect: "manual",
  });

  assert.equal(postAuthRes.status, 302);
  const redirectLocation = postAuthRes.headers.get("location");
  assert.ok(redirectLocation);
  assert.ok(redirectLocation.startsWith(dynamicRedirectUri));

  const authCode = new URL(redirectLocation).searchParams.get("code")!;

  // Exchange token
  const tokenRes = await fetch(`${serverBase}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: authCode,
      code_verifier: codeVerifier,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: dynamicRedirectUri,
    }).toString(),
  });

  assert.equal(tokenRes.status, 200);
  const tokenData = await tokenRes.json() as { access_token: string };

  // Call MCP
  const mcpRes = await fetch(`${serverBase}/mcp`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${tokenData.access_token}`,
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-03-26",
        capabilities: {},
        clientInfo: { name: "gemini-web", version: "1.0.0" },
      },
    }),
  });

  assert.equal(mcpRes.status, 200);
});

test("Gemini Web config via DEVSPACE_GEMINI_* environment variables", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "devspace-gemini-env-"));
  const publicBaseUrl = "https://agent.example.com";
  const envRedirectUri = "https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-env-test";
  const clientId = "gemini-env-client";
  const clientSecret = "env-secret-123456";

  const baseEnv = writeTestDevspaceConfig(join(root, "config"), {
    server: { publicBaseUrl },
    storage: { stateDir: join(root, "state") },
    workspaces: { allowedRoots: [root] },
    logging: { level: "silent" },
  });

  const config = loadConfig({
    ...baseEnv,
    DEVSPACE_GEMINI_CLIENT_ID: clientId,
    DEVSPACE_GEMINI_CLIENT_SECRET: clientSecret,
    DEVSPACE_GEMINI_REDIRECT_URI: envRedirectUri,
  });

  assert.equal(config.oauth.staticClients?.length, 1);
  assert.equal(config.oauth.staticClients?.[0].clientId, clientId);
  assert.equal(config.oauth.staticClients?.[0].clientSecret, clientSecret);
  assert.ok(config.oauth.staticClients?.[0].redirectUris.includes(envRedirectUri));

  const running = createServer(config);
  const listener = running.app.listen(0, "127.0.0.1");

  t.after(async () => {
    await running.close();
    listener.closeAllConnections();
    await new Promise<void>((resolve, reject) => listener.close((error) => error ? reject(error) : resolve()));
    await rm(root, { recursive: true, force: true });
  });

  await once(listener, "listening");
  const address = listener.address();
  assert.ok(address && typeof address !== "string");
  const serverBase = `http://127.0.0.1:${address.port}`;

  const codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url");

  // Submit approval directly
  const postAuthRes = await fetch(`${serverBase}/authorize`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: envRedirectUri,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      owner_token: "test-owner-token-that-is-long-enough",
    }).toString(),
    redirect: "manual",
  });

  assert.equal(postAuthRes.status, 302);
  const redirectLocation = postAuthRes.headers.get("location");
  assert.ok(redirectLocation);
  const authCode = new URL(redirectLocation).searchParams.get("code")!;

  // Exchange token
  const tokenRes = await fetch(`${serverBase}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: authCode,
      code_verifier: codeVerifier,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: envRedirectUri,
    }).toString(),
  });

  assert.equal(tokenRes.status, 200);
});

