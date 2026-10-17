/**
 * WorkOS AuthKit OAuth 2.1 resource-server guard for 掌心窗 MCP.
 *
 * Public (unauthenticated): GET /, GET /health, OPTIONS, and OAuth protected
 * resource metadata.  Every other route, including POST /mcp, /mcp-wallet,
 * GET /sse and POST /messages, requires a valid WorkOS access token from
 * the explicitly allowed user.  In particular, the guard is installed ahead
 * of express.json() and before all MCP routes.
 *
 * Never put LINJIAN_TOKEN in an OAuth token or client-facing response.
 */
import { createRemoteJWKSet, jwtVerify } from "jose";

function strictHttpsUrl(raw, name) {
  const value = String(raw ?? "").trim();
  if (!value) throw new Error(`${name} is required; refusing to start unprotected`);
  let url;
  try { url = new URL(value); }
  catch { throw new Error(`${name} must be an absolute HTTPS URL`); }
  if (
    url.protocol !== "https:" || url.username || url.password ||
    url.search || url.hash
  ) {
    throw new Error(`${name} must be an exact absolute HTTPS URL without query, fragment, or credentials`);
  }
  return url;
}

/** Must be called once, before the existing MCP endpoints are declared. */
export function installWorkOSAuth(app) {
  const issuerUrl = strictHttpsUrl(process.env.WORKOS_ISSUER, "WORKOS_ISSUER");
  const resourceUrl = strictHttpsUrl(process.env.WORKOS_RESOURCE, "WORKOS_RESOURCE");
  const issuer = issuerUrl.href.replace(/\/$/, "");
  const resource = resourceUrl.href;
  if (resourceUrl.pathname !== "/mcp") {
    throw new Error("WORKOS_RESOURCE must equal the publicly registered /mcp URL");
  }

  const allowedSub = new Set(
    String(process.env.WORKOS_ALLOWED_SUB ?? "")
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean)
  );
  if (allowedSub.size === 0 || [...allowedSub].some((sub) => !/^user_[A-Za-z0-9]+$/.test(sub))) {
    throw new Error("WORKOS_ALLOWED_SUB must list one or more valid WorkOS user_ IDs; refusing to start unprotected");
  }

  // Restrict key retrieval to a known endpoint on the configured issuer.
  const jwks = createRemoteJWKSet(new URL(`${issuer}/oauth2/jwks`));
  const metadataUrl = `${resourceUrl.origin}/.well-known/oauth-protected-resource`;
  const metadata = Object.freeze({
    resource,
    authorization_servers: [issuer],
    bearer_methods_supported: ["header"],
  });

  // Both root and path-specific discovery forms are permitted by RFC 9728.
  app.get(
    [
      "/.well-known/oauth-protected-resource",
      "/.well-known/oauth-protected-resource/mcp",
      "/.well-known/oauth-protected-resource/mcp-wallet",
    ],
    (_req, res) => res.set("Cache-Control", "public, max-age=300").json(metadata)
  );

  // Keep unauthenticated readiness checks minimal; hide upstream URL and tool list.
  app.get("/health", (_req, res) => res.json({ ok: true, service: "linjian-public-mcp", auth: "workos" }));

  const challenge = (error = "") => {
    const base = `Bearer resource_metadata="${metadataUrl}"`;
    return error ? `${base}, error="invalid_token"` : base;
  };

  app.use(async (req, res, next) => {
    // OPTIONS is already handled by the existing CORS middleware.  No tools
    // or private information are exposed by these two public readiness paths.
    if ((req.method === "GET" || req.method === "HEAD") && req.path === "/") return next();
    if (req.method === "OPTIONS") return res.status(204).end();

    const match = /^Bearer\s+([^\s]+)$/i.exec(req.get("Authorization") || "");
    if (!match) {
      return res.set("Cache-Control", "no-store")
        .set("WWW-Authenticate", challenge())
        .status(401).json({ error: "authorization_required" });
    }
    try {
      const { payload } = await jwtVerify(match[1], jwks, {
        issuer,
        audience: resource,
        algorithms: ["RS256"],
      });
      if (!Number.isInteger(payload.exp) || !Number.isInteger(payload.iat)) {
        return res.set("Cache-Control", "no-store")
          .set("WWW-Authenticate", challenge("invalid_token"))
          .status(401).json({ error: "invalid_token" });
      }
      if (typeof payload.sub !== "string" || !allowedSub.has(payload.sub)) {
        return res.set("Cache-Control", "no-store").status(403).json({ error: "forbidden" });
      }
      // The user allowlist excludes client-credentials (M2M) subjects.
      // WorkOS user access tokens also carry the issuing client ID.
      if (typeof payload.client_id !== "string") {
        return res.set("Cache-Control", "no-store")
          .set("WWW-Authenticate", challenge("invalid_token"))
          .status(401).json({ error: "invalid_token" });
      }
      req.workosUser = { sub: payload.sub };
      return next();
    } catch (_err) {
      // Fail closed on an invalid, expired, mis-audienced token or JWKS error.
      // Do not expose the token or verification details to clients or logs.
      return res.set("Cache-Control", "no-store")
        .set("WWW-Authenticate", challenge("invalid_token"))
        .status(401).json({ error: "invalid_token" });
    }
  });
}
