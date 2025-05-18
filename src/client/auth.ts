import pkceChallenge from "pkce-challenge";
import { LATEST_PROTOCOL_VERSION } from "../types.js";
import type { OAuthClientMetadata, OAuthClientInformation, OAuthTokens, OAuthMetadata, OAuthClientInformationFull } from "../shared/auth.js";
import { OAuthClientInformationFullSchema, OAuthMetadataSchema, OAuthTokensSchema } from "../shared/auth.js";

/**
 * Implements an end-to-end OAuth client to be used with one MCP server.
 * 
 * This client relies upon a concept of an authorized "session," the exact
 * meaning of which is application-defined. Tokens, authorization codes, and
 * code verifiers should not cross different sessions.
 */
export interface OAuthClientProvider {
  /**
   * The URL to redirect the user agent to after authorization.
   */
  get redirectUrl(): string | URL;

  /**
   * Metadata about this OAuth client.
   */
  get clientMetadata(): OAuthClientMetadata;

  /**
   * Loads information about this OAuth client, as registered already with the
   * server, or returns `undefined` if the client is not registered with the
   * server.
   */
  clientInformation(): OAuthClientInformation | undefined | Promise<OAuthClientInformation | undefined>;

  /**
   * If implemented, this permits the OAuth client to dynamically register with
   * the server. Client information saved this way should later be read via
   * `clientInformation()`.
   * 
   * This method is not required to be implemented if client information is
   * statically known (e.g., pre-registered).
   */
  saveClientInformation?(clientInformation: OAuthClientInformationFull): void | Promise<void>;

  /**
   * Loads any existing OAuth tokens for the current session, or returns
   * `undefined` if there are no saved tokens.
   */
  tokens(): OAuthTokens | undefined | Promise<OAuthTokens | undefined>;

  /**
   * Stores new OAuth tokens for the current session, after a successful
   * authorization.
   */
  saveTokens(tokens: OAuthTokens): void | Promise<void>;

  /**
   * Invoked to redirect the user agent to the given URL to begin the authorization flow.
   */
  redirectToAuthorization(authorizationUrl: URL): void | Promise<void>;

  /**
   * Saves a PKCE code verifier for the current session, before redirecting to
   * the authorization flow.
   */
  saveCodeVerifier(codeVerifier: string): void | Promise<void>;

  /**
   * Loads the PKCE code verifier for the current session, necessary to validate
   * the authorization result.
   */
  codeVerifier(): string | Promise<string>;
}

export type AuthResult = "AUTHORIZED" | "REDIRECT";

export class UnauthorizedError extends Error {
  constructor(message?: string) {
    super(message ?? "Unauthorized");
  }
}

/**
 * Orchestrates the full auth flow with a server.
 * 
 * This can be used as a single entry point for all authorization functionality,
 * instead of linking together the other lower-level functions in this module.
 */
export async function auth(
  provider: OAuthClientProvider,
  { serverUrl, authorizationCode }: { serverUrl: string | URL, authorizationCode?: string }): Promise<AuthResult> {
    let protectedMeta;
    const authzUrlBase = typeof serverUrl === "string" ? serverUrl : serverUrl.toString();
    if (authzUrlBase.includes("/.well-known/oauth-protected-resource")) {
        protectedMeta = await discoverProtectedResourceMetadata(serverUrl);
        if (protectedMeta.scopes_supported) {
            const s = protectedMeta.scopes_supported;
            if (Array.isArray(s)) {
              provider.clientMetadata.scope = s.join(" ");
            } else if (typeof s === "object") {
              const scopes = Object.values(s);
              const unique = Array.from(new Set(scopes));
              provider.clientMetadata.scope = unique.join(" ");
            } else if (typeof s === "string") {
                provider.clientMetadata.scope = s;
            } else {
              throw new Error(
                `unsupported scopes_supported type ${typeof s}`
              );
            }
        }
        
        const issuer = protectedMeta.authorization_servers[0].replace(/\/+$|\/$/, "");
        serverUrl = new URL(issuer);
    }

  const metadata = await discoverOAuthMetadata(serverUrl);

  let clientInformation = await Promise.resolve(
    provider.clientInformation()
  );
  if (!clientInformation) {
    if (authorizationCode !== undefined) {
      throw new Error(
        "Existing OAuth client information is required when exchanging an authorization code"
      );
    }

    if (!provider.saveClientInformation) {
      throw new Error(
        "OAuth client information must be saveable for dynamic registration"
      );
    }
    const fullInfo = await registerClient(serverUrl, {
      metadata,
      clientMetadata: provider.clientMetadata
    });

    await provider.saveClientInformation(fullInfo);
    clientInformation = fullInfo;
  }

  if (authorizationCode !== undefined) {
    const codeVerifier = await provider.codeVerifier();
    const tokens = await exchangeAuthorization(serverUrl, {
      metadata,
      clientInformation,
      authorizationCode,
      codeVerifier,
      redirectUri: provider.redirectUrl
    });

    await provider.saveTokens(tokens);
    return "AUTHORIZED";
  }

  const tokens = await provider.tokens();
  if (tokens?.refresh_token) {
    try {
      const newTokens = await refreshAuthorization(serverUrl, {
        metadata,
        clientInformation,
        refreshToken: tokens.refresh_token
      });
      await provider.saveTokens(newTokens);
      return "AUTHORIZED";
    } catch (_) {
      console.error("Could not refresh OAuth tokens");
    }
  }

  // Start new authorization flow
  const { authorizationUrl, codeVerifier } = await startAuthorization(serverUrl, {
    metadata,
    clientInformation,
    redirectUrl: provider.redirectUrl,
    scope: "openid profile email mcp_proxy"
  });

  console.log("Starting authorization flow with URL:", authorizationUrl.toString());
  await provider.saveCodeVerifier(codeVerifier);
  console.log("Saved code verifier");
  await provider.redirectToAuthorization(authorizationUrl);
  console.log("Redirected to authorization URL");
  return "REDIRECT";
}

/**
 * Discover Protected-Resource Metadata (RFC 9728)
 */
export async function discoverProtectedResourceMetadata(serverUrl: string | URL) {
    const url = typeof serverUrl === "string" ? serverUrl : serverUrl.toString();
    const res = await fetch(url, {
      headers: { "MCP-Protocol-Version": LATEST_PROTOCOL_VERSION }
    });

    if (!res.ok) {
      throw new Error(
        `HTTP ${res.status} trying to load protected-resource metadata`
      );
    }

    return await res.json();
} 

/**
 * Begins the authorization flow with the given server, by generating a PKCE challenge and constructing the authorization URL.
 */
export async function startAuthorization(
  serverUrl: string | URL,
  {
    metadata,
    clientInformation,
    redirectUrl,
    scope,
  }: {
    metadata?: OAuthMetadata;
    clientInformation: OAuthClientInformation;
    redirectUrl: string | URL;
    scope?: string;
  },
): Promise<{ authorizationUrl: URL; codeVerifier: string }> {
  const responseType = "code";
  const codeChallengeMethod = "S256";

  let authorizationUrl: URL;
  if (metadata) {
    authorizationUrl = new URL(metadata.authorization_endpoint);

    if (!metadata.response_types_supported.includes(responseType)) {
      throw new Error(
        `Incompatible auth server: does not support response type ${responseType}`,
      );
    }

    if (
      !metadata.code_challenge_methods_supported ||
      !metadata.code_challenge_methods_supported.includes(codeChallengeMethod)
    ) {
      throw new Error(
        `Incompatible auth server: does not support code challenge method ${codeChallengeMethod}`,
      );
    }
  } else {
    authorizationUrl = new URL("/authorize", serverUrl);
  }

  // Generate PKCE challenge
  const challenge = await pkceChallenge();
  const codeVerifier = challenge.code_verifier;
  const codeChallenge = challenge.code_challenge;

  authorizationUrl.searchParams.set("response_type", responseType);
  authorizationUrl.searchParams.set("client_id", clientInformation.client_id);
  authorizationUrl.searchParams.set("code_challenge", codeChallenge);
  authorizationUrl.searchParams.set(
    "code_challenge_method",
    codeChallengeMethod,
  );
  authorizationUrl.searchParams.set("redirect_uri", String(redirectUrl));
  authorizationUrl.searchParams.set("audience", "mcp_proxy");
  if (scope) {
    authorizationUrl.searchParams.set("scope", scope);
  }

  return { authorizationUrl, codeVerifier };
}

/**
 * Exchanges an authorization code for an access token with the given server.
 */
export async function exchangeAuthorization(
  serverUrl: string | URL,
  {
    metadata,
    clientInformation,
    authorizationCode,
    codeVerifier,
    redirectUri,
  }: {
    metadata?: OAuthMetadata;
    clientInformation: OAuthClientInformation;
    authorizationCode: string;
    codeVerifier: string;
    redirectUri: string | URL;
  },
): Promise<OAuthTokens> {
  const grantType = "authorization_code";

  let tokenUrl: URL;
  if (metadata) {
    tokenUrl = new URL(metadata.token_endpoint);

    if (
      metadata.grant_types_supported &&
      !metadata.grant_types_supported.includes(grantType)
    ) {
      throw new Error(
        `Incompatible auth server: does not support grant type ${grantType}`,
      );
    }
  } else {
    tokenUrl = new URL("/token", serverUrl);
  }

  // Exchange code for tokens
  const params = new URLSearchParams({
    grant_type: grantType,
    client_id: clientInformation.client_id,
    code: authorizationCode,
    code_verifier: codeVerifier,
    redirect_uri: String(redirectUri),
    audience: "mcp_proxy",
    scope: "openid profile email mcp_proxy",
  });

  if (clientInformation.client_secret) {
    params.set("client_secret", clientInformation.client_secret);
  }

  const response = await fetch(tokenUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: params,
  });

  if (!response.ok) {
    throw new Error(`Token exchange failed: HTTP ${response.status}`);
  }

  return OAuthTokensSchema.parse(await response.json());
}

/**
 * Exchange a refresh token for an updated access token.
 */
export async function refreshAuthorization(
  serverUrl: string | URL,
  {
    metadata,
    clientInformation,
    refreshToken,
  }: {
    metadata?: OAuthMetadata;
    clientInformation: OAuthClientInformation;
    refreshToken: string;
  },
): Promise<OAuthTokens> {
  const grantType = "refresh_token";

  let tokenUrl: URL;
  if (metadata) {
    tokenUrl = new URL(metadata.token_endpoint);

    if (
      metadata.grant_types_supported &&
      !metadata.grant_types_supported.includes(grantType)
    ) {
      throw new Error(
        `Incompatible auth server: does not support grant type ${grantType}`,
      );
    }
  } else {
    tokenUrl = new URL("/token", serverUrl);
  }

  // Exchange refresh token
  const params = new URLSearchParams({
    grant_type: grantType,
    client_id: clientInformation.client_id,
    refresh_token: refreshToken,
  });

  if (clientInformation.client_secret) {
    params.set("client_secret", clientInformation.client_secret);
  }

  const response = await fetch(tokenUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: params,
  });

  if (!response.ok) {
    throw new Error(`Token refresh failed: HTTP ${response.status}`);
  }

  return OAuthTokensSchema.parse(await response.json());
}

/**
 * Performs OAuth 2.0 Dynamic Client Registration according to RFC 7591.
 */
export async function registerClient(
  serverUrl: string | URL,
  {
    metadata,
    clientMetadata,
  }: {
    metadata?: OAuthMetadata;
    clientMetadata: OAuthClientMetadata;
  },
): Promise<OAuthClientInformationFull> {
  let registrationUrl: URL;

  if (metadata) {
    if (!metadata.registration_endpoint) {
      throw new Error("Incompatible auth server: does not support dynamic client registration");
    }

    registrationUrl = new URL(metadata.registration_endpoint);
  } else {
    registrationUrl = new URL("/register", serverUrl);
  }

  const response = await fetch(registrationUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(clientMetadata),
  });

  if (!response.ok) {
    throw new Error(`Dynamic client registration failed: HTTP ${response.status}`);
  }

  return OAuthClientInformationFullSchema.parse(await response.json());
}

async function fetchMaybe(
  url: URL,
  init?: RequestInit
): Promise<Response> {
  try {
    return await fetch(url, init);
  } catch (err) {
    if (err instanceof TypeError) {
        return await fetch(url);
    }
    throw err;
  }
}

export async function discoverOAuthMetadata(
  serverUrl: string | URL,
  opts?: { protocolVersion?: string }
): Promise<OAuthMetadata> {
  const base = typeof serverUrl === "string" ? serverUrl : serverUrl.toString();
  const headers = {
    "MCP-Protocol-Version": opts?.protocolVersion ?? LATEST_PROTOCOL_VERSION,
  };

  const oauthUrl = new URL("/.well-known/oauth-authorization-server", base);
  let oauthResp: Response;
  try {
    oauthResp = await fetchMaybe(oauthUrl, { headers });
  } catch (e) {
    // If OAuth endpoint fails completely, try OIDC
    return await discoverViaOidc(base, headers);
  }

  if (oauthResp.ok) {
    const payload = await oauthResp.json();
    return OAuthMetadataSchema.parse(payload);
  }

  // 404 / 401 / 403 from the OAuth endpoint → fallback to OIDC
  if ([404, 401, 403].includes(oauthResp.status)) {
    return await discoverViaOidc(base, headers);
  }

  // any other HTTP error is fatal
  throw new Error(`OAuth metadata discovery failed: HTTP ${oauthResp.status}`);
}

async function discoverViaOidc(
  base: string,
  headers: Record<string,string>
): Promise<OAuthMetadata> {
  const oidcUrl = new URL("/.well-known/openid-configuration", base);
  const oidcResp = await fetchMaybe(oidcUrl, { headers });

  if (!oidcResp.ok) {
    throw new Error(`OIDC discovery failed: HTTP ${oidcResp.status}`);
  }

  const doc = await oidcResp.json();
  return OAuthMetadataSchema.parse(doc);
}