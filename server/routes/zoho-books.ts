import crypto from "node:crypto";
import { RequestHandler } from "express";
import { createClient, SupabaseClient } from "@supabase/supabase-js";

const zohoAccountsUrl = process.env.ZOHO_ACCOUNTS_URL || "https://accounts.zoho.com";
const zohoApiUrl = process.env.ZOHO_BOOKS_API_URL || "https://www.zohoapis.com/books/v3";
const redirectPath = "/books/callback";

type ZohoIntegration = {
  user_id: string;
  access_token: string | null;
  refresh_token: string | null;
  token_expires_at: string | null;
  organization_id: string | null;
  is_connected: boolean | null;
  connected_at: string | null;
};

const getConfig = () => {
  const clientId = process.env.APP_ZOHO_CLIENT_ID || process.env.ZOHO_CLIENT_ID || process.env.VITE_ZOHO_CLIENT_ID;
  const clientSecret = process.env.APP_ZOHO_CLIENT_SECRET || process.env.ZOHO_CLIENT_SECRET;
  const redirectUri = process.env.APP_ZOHO_REDIRECT_URI || process.env.ZOHO_REDIRECT_URI || process.env.VITE_ZOHO_REDIRECT_URI;
  const supabaseUrl = process.env.APP_SUPABASE_URL || process.env.VITE_SUPABASE_URL || process.env.SUPABASE_URL;
  let serviceRoleKey = process.env.APP_SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!serviceRoleKey && process.env.SUPABASE_SECRET_KEYS) {
    try {
      const secretKeys = JSON.parse(process.env.SUPABASE_SECRET_KEYS) as Record<string, string>;
      serviceRoleKey = secretKeys.service_role || secretKeys.default || secretKeys.SUPABASE_SERVICE_ROLE_KEY;
    } catch {
      throw new Error("SUPABASE_SECRET_KEYS is not valid JSON");
    }
  }

  const missing: string[] = [];
  if (!clientId) missing.push("ZOHO_CLIENT_ID (or VITE_ZOHO_CLIENT_ID)");
  if (!clientSecret) missing.push("ZOHO_CLIENT_SECRET");
  if (!redirectUri) missing.push("ZOHO_REDIRECT_URI (or VITE_ZOHO_REDIRECT_URI)");
  if (!supabaseUrl) missing.push("APP_SUPABASE_URL");
  if (!serviceRoleKey) missing.push("APP_SUPABASE_SECRET_KEY");

  if (missing.length > 0) {
    throw new Error(`Zoho Books server configuration is incomplete. Missing server variable(s): ${missing.join(", ")}`);
  }

  return { clientId, clientSecret, redirectUri, supabaseUrl, serviceRoleKey };
};

const getAdminClient = () => {
  const { supabaseUrl, serviceRoleKey } = getConfig();
  return createClient(supabaseUrl, serviceRoleKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });
};

const getUserId = async (authorization: string | undefined) => {
  if (!authorization?.startsWith("Bearer ")) return null;
  const token = authorization.slice("Bearer ".length);
  const { supabaseUrl } = getConfig();
  const anonKey = process.env.APP_SUPABASE_ANON_KEY || process.env.VITE_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY || process.env.SUPABASE_PUBLISHABLE_KEY;
  if (!anonKey) throw new Error("Supabase anonymous/publishable key is not configured for the server");

  const client = createClient(supabaseUrl, anonKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });
  const { data, error } = await client.auth.getUser(token);
  if (error || !data.user) return null;
  return data.user.id;
};

const requireUser = async (authorization: string | undefined, res: Parameters<RequestHandler>[1]) => {
  const userId = await getUserId(authorization);
  if (!userId) {
    res.status(401).json({ error: "Authentication required" });
    return null;
  }
  return userId;
};

const encodeState = (userId: string) => {
  const { clientSecret } = getConfig();
  const payload = Buffer.from(JSON.stringify({ userId, expiresAt: Date.now() + 10 * 60 * 1000 })).toString("base64url");
  const signature = crypto.createHmac("sha256", clientSecret).update(payload).digest("base64url");
  return `${payload}.${signature}`;
};

const verifyState = (state: string, userId: string) => {
  const { clientSecret } = getConfig();
  const [payload, signature] = state.split(".");
  if (!payload || !signature) return false;
  const expected = crypto.createHmac("sha256", clientSecret).update(payload).digest("base64url");
  const receivedBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expected);
  if (receivedBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(receivedBuffer, expectedBuffer)) return false;

  const parsed = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as {
    userId: string;
    expiresAt: number;
  };
  return parsed.userId === userId && parsed.expiresAt > Date.now();
};

const getIntegration = async (admin: SupabaseClient, userId: string) => {
  const { data, error } = await admin
    .from("zoho_books_integrations")
    .select("user_id, access_token, refresh_token, token_expires_at, organization_id, is_connected, connected_at")
    .eq("user_id", userId)
    .maybeSingle();
  if (error) throw error;
  return data as ZohoIntegration | null;
};

const saveTokens = async (
  admin: SupabaseClient,
  userId: string,
  tokens: { access_token: string; refresh_token?: string; expires_in?: number },
) => {
  const { error } = await admin.from("zoho_books_integrations").upsert({
    user_id: userId,
    access_token: tokens.access_token,
    ...(tokens.refresh_token ? { refresh_token: tokens.refresh_token } : {}),
    token_expires_at: new Date(Date.now() + (tokens.expires_in || 3600) * 1000).toISOString(),
    is_connected: true,
    connected_at: new Date().toISOString(),
    disconnected_at: null,
    updated_at: new Date().toISOString(),
  }, { onConflict: "user_id" });
  if (error) throw error;
};

const refreshAccessToken = async (admin: SupabaseClient, integration: ZohoIntegration) => {
  if (!integration.refresh_token) throw new Error("Zoho refresh token is unavailable");
  const { clientId, clientSecret } = getConfig();
  const response = await fetch(`${zohoAccountsUrl}/oauth/v2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      refresh_token: integration.refresh_token,
      client_id: clientId,
      client_secret: clientSecret,
      grant_type: "refresh_token",
    }),
  });
  const tokens = await response.json() as { access_token?: string; expires_in?: number; error?: string };
  if (!response.ok || !tokens.access_token) throw new Error(tokens.error || "Zoho token refresh failed");
  await saveTokens(admin, integration.user_id, {
    access_token: tokens.access_token,
    expires_in: tokens.expires_in,
  });
  return tokens.access_token;
};

const getAccessToken = async (admin: SupabaseClient, integration: ZohoIntegration) => {
  if (!integration.access_token) throw new Error("Zoho is not connected");
  const expiresAt = integration.token_expires_at ? Date.parse(integration.token_expires_at) : 0;
  if (expiresAt > Date.now() + 60_000) return integration.access_token;
  return refreshAccessToken(admin, integration);
};

const zohoFetch = async (admin: SupabaseClient, integration: ZohoIntegration, path: string) => {
  const accessToken = await getAccessToken(admin, integration);
  const response = await fetch(`${zohoApiUrl}${path}`, {
    headers: { Authorization: `Zoho-oauthtoken ${accessToken}` },
  });
  const data = await response.json() as { code?: number; message?: string; [key: string]: unknown };
  if (!response.ok || (typeof data.code === "number" && data.code !== 0)) {
    throw new Error(data.message || "Zoho Books request failed");
  }
  return data;
};

export const startZohoBooksConnect: RequestHandler = async (req, res) => {
  try {
    const userId = await requireUser(req.headers.authorization, res);
    if (!userId) return;
    const { clientId, redirectUri } = getConfig();
    const params = new URLSearchParams({
      client_id: clientId,
      response_type: "code",
      redirect_uri: redirectUri,
      scope: "ZohoBooks.contacts.READ,ZohoBooks.invoices.READ,ZohoBooks.settings.READ",
      access_type: "offline",
      prompt: "consent",
      state: encodeState(userId),
    });
    res.json({ url: `${zohoAccountsUrl}/oauth/v2/auth?${params.toString()}` });
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : "Unable to start Zoho connection" });
  }
};

const completeAuthorization = async (userId: string, code: string, state: string) => {
  if (!verifyState(state, userId)) throw new Error("Invalid or expired Zoho authorization");

  const { clientId, clientSecret, redirectUri } = getConfig();
  const response = await fetch(`${zohoAccountsUrl}/oauth/v2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
      grant_type: "authorization_code",
    }),
  });
  const tokens = await response.json() as { access_token?: string; refresh_token?: string; expires_in?: number; error?: string };
  if (!response.ok || !tokens.access_token) throw new Error(tokens.error || "Zoho authorization failed");

  const admin = getAdminClient();
  await saveTokens(admin, userId, {
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token,
    expires_in: tokens.expires_in,
  });

  const integration = await getIntegration(admin, userId);
  if (integration) {
    const organizations = await zohoFetch(admin, integration, "/organizations");
    const firstOrganization = (organizations.organizations as Array<{ organization_id: string }> | undefined)?.[0];
    if (firstOrganization) {
      const { error } = await admin
        .from("zoho_books_integrations")
        .update({ organization_id: firstOrganization.organization_id })
        .eq("user_id", userId);
      if (error) throw error;
    }
  }
};

const getStateUserId = (state: string) => {
  const [payload] = state.split(".");
  if (!payload) throw new Error("Invalid Zoho authorization state");
  const parsed = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as { userId?: string };
  if (!parsed.userId) throw new Error("Invalid Zoho authorization state");
  return parsed.userId;
};

const getBooksRedirectUri = (req: Parameters<RequestHandler>[0], error?: string) => {
  const protocol = req.headers["x-forwarded-proto"]?.toString().split(",")[0] || req.protocol;
  const booksUrl = new URL("/books", `${protocol}://${req.get("host")}`);
  booksUrl.search = error ? `?error=${encodeURIComponent(error)}` : "?connected=1";
  return booksUrl.toString();
};

export const completeZohoBooksCallback: RequestHandler = async (req, res) => {
  const code = typeof req.query.code === "string" ? req.query.code : "";
  const state = typeof req.query.state === "string" ? req.query.state : "";
  try {
    if (!code || !state) throw new Error("Zoho authorization was not completed");
    const userId = getStateUserId(state);
    await completeAuthorization(userId, code, state);
    res.redirect(302, getBooksRedirectUri(req));
  } catch (error) {
    res.redirect(302, getBooksRedirectUri(req, "authorization"));
  }
};

export const completeZohoBooksConnect: RequestHandler = async (req, res) => {
  try {
    const userId = await requireUser(req.headers.authorization, res);
    if (!userId) return;
    const { code, state } = req.body as { code?: string; state?: string };
    if (!code || !state) {
      res.status(400).json({ error: "Invalid or expired Zoho authorization" });
      return;
    }
    await completeAuthorization(userId, code, state);
    res.json({ connected: true });
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : "Unable to complete Zoho connection" });
  }
};

export const getZohoBooksStatus: RequestHandler = async (req, res) => {
  try {
    const userId = await requireUser(req.headers.authorization, res);
    if (!userId) return;
    const integration = await getIntegration(getAdminClient(), userId);
    res.json({
      connected: Boolean(integration?.is_connected && integration.access_token),
      organizationId: integration?.organization_id || null,
      connectedAt: integration?.connected_at || null,
    });
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : "Unable to load Zoho status" });
  }
};

export const getZohoBooksData: RequestHandler = async (req, res) => {
  try {
    const userId = await requireUser(req.headers.authorization, res);
    if (!userId) return;
    const admin = getAdminClient();
    const integration = await getIntegration(admin, userId);
    if (!integration?.is_connected || !integration.organization_id) {
      res.status(409).json({ error: "Connect a Zoho Books organization first" });
      return;
    }
    const query = `?organization_id=${encodeURIComponent(integration.organization_id)}`;
    const [invoices, contacts] = await Promise.all([
      zohoFetch(admin, integration, `/invoices${query}&per_page=5&sort_column=last_modified_time`),
      zohoFetch(admin, integration, `/contacts${query}&per_page=5`),
    ]);
    res.json({
      invoices: invoices.invoices || [],
      contacts: contacts.contacts || [],
      organizationId: integration.organization_id,
    });
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : "Unable to load Zoho Books data" });
  }
};

export const disconnectZohoBooks: RequestHandler = async (req, res) => {
  try {
    const userId = await requireUser(req.headers.authorization, res);
    if (!userId) return;
    const { error } = await getAdminClient().from("zoho_books_integrations").update({
      access_token: null,
      refresh_token: null,
      token_expires_at: null,
      organization_id: null,
      is_connected: false,
      disconnected_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    }).eq("user_id", userId);
    if (error) throw error;
    res.json({ connected: false });
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : "Unable to disconnect Zoho" });
  }
};
