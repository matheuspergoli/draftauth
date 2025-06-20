import type { StandardSchemaV1 } from "@standard-schema/spec"
/**
 * Draft Auth client for OAuth 2.0 and OpenID Connect authentication.
 *
 * ## Quick Start
 *
 * First, create a client.
 *
 * ```ts title="client.ts"
 * import { createClient } from "@draftauth/core/client"
 *
 * const client = createClient({
 *   clientID: "my-client",
 *   issuer: "https://auth.myserver.com"
 * })
 * ```
 *
 * Start the OAuth flow by calling `authorize`.
 *
 * ```ts
 * const result = await client.authorize(
 *   "https://myapp.com/callback",
 *   "code"
 * )
 * if (result.success) {
 *   window.location.href = result.data.url
 * }
 * ```
 *
 * When the user completes the flow, exchange the code for tokens.
 *
 * ```ts
 * const result = await client.exchange(code, redirectUri)
 * if (result.success) {
 *   const { access, refresh } = result.data
 *   // Store tokens securely
 * }
 * ```
 *
 * Verify tokens to get user information.
 *
 * ```ts
 * const result = await client.verify(subjects, accessToken)
 * if (result.success) {
 *   // Access user properties: result.data.subject.properties
 * }
 * ```
 *
 * @packageDocumentation
 */
import { createLocalJWKSet, errors, type JSONWebKeySet, jwtVerify } from "jose"
import {
	InvalidAccessTokenError,
	InvalidAuthorizationCodeError,
	InvalidRefreshTokenError,
	InvalidSubjectError,
	TokenRevocationError,
	UnsupportedTokenTypeError
} from "./error"
import { generatePKCE } from "./pkce"
import type { SubjectSchema } from "./subject"

/**
 * Result type for operations that can succeed or fail.
 *
 * @template T - The success data type
 * @template E - The error type
 *
 * @example
 * ```ts
 * const result = await client.exchange(code, redirectUri)
 * if (result.success) {
 *   // Access token available: result.data.access
 * } else {
 *   // Handle error: result.error.message
 * }
 * ```
 */
export type Result<T, E = Error> = { success: true; data: T } | { success: false; error: E }

interface TokenResponse {
	access_token: string
	refresh_token: string
	expires_in: number
	id_token?: string
	scope?: string
}

interface FetchResponse {
	json(): Promise<unknown>
	text(): Promise<string>
	ok: boolean
	status: number
}

type FetchLike = (url: string, init?: RequestInit) => Promise<FetchResponse>

/**
 * Authorization server metadata from well-known endpoints.
 */
export interface WellKnown {
	/**
	 * URI to the JWKS endpoint for token verification.
	 */
	jwks_uri: string
	/**
	 * URI to the token endpoint for authorization code exchange.
	 */
	token_endpoint: string
	/**
	 * URI to the authorization endpoint for starting flows.
	 */
	authorization_endpoint: string
	/**
	 * The issuer identifier.
	 */
	issuer: string
	/**
	 * URI to the UserInfo endpoint.
	 */
	userinfo_endpoint?: string
	/**
	 * URI to the logout endpoint.
	 */
	end_session_endpoint?: string
	/**
	 * URI to the token revocation endpoint.
	 */
	revocation_endpoint?: string
	/**
	 * Supported OAuth 2.0 scope values.
	 */
	scopes_supported?: string[]
	/**
	 * Supported claims.
	 */
	claims_supported?: string[]
	/**
	 * Supported OAuth 2.0 response types.
	 */
	response_types_supported?: string[]
	/**
	 * Supported OAuth 2.0 grant types.
	 */
	grant_types_supported?: string[]
	/**
	 * Supported subject identifier types.
	 */
	subject_types_supported?: string[]
	/**
	 * Supported ID token signing algorithms.
	 */
	id_token_signing_alg_values_supported?: string[]
	/**
	 * Supported OAuth 2.0 response modes.
	 */
	response_modes_supported?: string[]
	/**
	 * Supported token endpoint authentication methods.
	 */
	token_endpoint_auth_methods_supported?: string[]
	/**
	 * Whether the claims parameter is supported.
	 */
	claims_parameter_supported?: boolean
	/**
	 * Whether the request parameter is supported.
	 */
	request_parameter_supported?: boolean
	/**
	 * Whether the request_uri parameter is supported.
	 */
	request_uri_parameter_supported?: boolean
	/**
	 * Whether request_uri registration is required.
	 */
	require_request_uri_registration?: boolean
	/**
	 * Supported revocation endpoint authentication methods.
	 */
	revocation_endpoint_auth_methods_supported?: string[]
}

/**
 * Tokens returned by the authorization server.
 */
export interface Tokens {
	/**
	 * Access token for making authenticated API requests.
	 */
	access: string
	/**
	 * Refresh token for obtaining new access tokens.
	 */
	refresh: string
	/**
	 * Number of seconds until the access token expires.
	 */
	expiresIn: number
	/**
	 * OIDC ID token (when openid scope is requested).
	 */
	idToken?: string
	/**
	 * Granted scopes as a space-separated string.
	 */
	scope?: string
}

/**
 * Challenge data for PKCE flows.
 */
export type Challenge = {
	/**
	 * State parameter for CSRF protection.
	 */
	state: string
	/**
	 * PKCE code verifier for token exchange.
	 */
	verifier?: string
}

/**
 * Client configuration options.
 */
export interface ClientInput {
	/**
	 * Client ID that identifies your application.
	 *
	 * @example
	 * ```ts
	 * {
	 *   clientID: "my-web-app"
	 * }
	 * ```
	 */
	clientID: string
	/**
	 * Base URL of your Draft Auth server.
	 *
	 * Can also be set via DRAFTAUTH_ISSUER environment variable.
	 *
	 * @example
	 * ```ts
	 * {
	 *   issuer: "https://auth.myserver.com"
	 * }
	 * ```
	 */
	issuer?: string
	/**
	 * Client secret for machine-to-machine authentication.
	 * Required for client credentials flow.
	 *
	 * @example
	 * ```ts
	 * {
	 *   clientSecret: process.env.CLIENT_SECRET
	 * }
	 * ```
	 */
	clientSecret?: string
	/**
	 * Custom fetch implementation for HTTP requests.
	 *
	 * @example
	 * ```ts
	 * {
	 *   fetch: customFetch
	 * }
	 * ```
	 */
	fetch?: FetchLike
}

/**
 * Options for starting an authorization flow.
 */
export interface AuthorizeOptions {
	/**
	 * Enable PKCE flow for enhanced security.
	 *
	 * Recommended for single-page applications and mobile apps.
	 *
	 * @default false
	 * @example
	 * ```ts
	 * {
	 *   pkce: true
	 * }
	 * ```
	 */
	pkce?: boolean
	/**
	 * Specific authentication provider to use.
	 *
	 * If not specified, users see a provider selection screen
	 * or are redirected to the single configured provider.
	 *
	 * @example
	 * ```ts
	 * {
	 *   provider: "google"
	 * }
	 * ```
	 */
	provider?: string
	/**
	 * OAuth 2.0 scopes to request.
	 *
	 * Determines what data your application can access.
	 *
	 * @example
	 * ```ts
	 * {
	 *   scopes: ["openid", "profile", "email"]
	 * }
	 * ```
	 */
	scopes?: string[]
	/**
	 * Nonce parameter for preventing replay attacks in ID tokens.
	 *
	 * @example
	 * ```ts
	 * {
	 *   nonce: crypto.randomUUID()
	 * }
	 * ```
	 */
	nonce?: string
	/**
	 * Prompt parameter controlling authentication behavior.
	 *
	 * - `none`: No authentication UI. Fails if user not authenticated.
	 * - `login`: Force user to re-authenticate.
	 *
	 * @example
	 * ```ts
	 * {
	 *   prompt: "login"
	 * }
	 * ```
	 */
	prompt?: "none" | "login"
	/**
	 * Maximum authentication age in seconds.
	 *
	 * If user's session is older, they'll be prompted to re-authenticate.
	 *
	 * @example
	 * ```ts
	 * {
	 *   maxAge: 3600 // 1 hour
	 * }
	 * ```
	 */
	maxAge?: number
	/**
	 * ID token hint for logout flows or user identification.
	 *
	 * @example
	 * ```ts
	 * {
	 *   idTokenHint: previousIdToken
	 * }
	 * ```
	 */
	idTokenHint?: string
	/**
	 * Login hint to pre-populate the username field.
	 *
	 * @example
	 * ```ts
	 * {
	 *   loginHint: "user@example.com"
	 * }
	 * ```
	 */
	loginHint?: string
}

/**
 * Result of starting an authorization flow.
 */
export interface AuthorizeResult {
	/**
	 * Challenge data needed for PKCE flows.
	 *
	 * Store this securely and use when exchanging the code.
	 *
	 * @example
	 * ```ts
	 * sessionStorage.setItem("challenge", JSON.stringify(challenge))
	 * ```
	 */
	challenge: Challenge
	/**
	 * Authorization URL to redirect the user to.
	 *
	 * @example
	 * ```ts
	 * window.location.href = url
	 * ```
	 */
	url: string
}

/**
 * Options for token refresh operations.
 */
export interface RefreshOptions {
	/**
	 * Current access token to check before refreshing.
	 *
	 * Helps avoid unnecessary refresh requests.
	 *
	 * @example
	 * ```ts
	 * {
	 *   access: currentAccessToken
	 * }
	 * ```
	 */
	access?: string
}

/**
 * Options for token verification.
 */
export interface VerifyOptions {
	/**
	 * Refresh token for automatic refresh if access token is expired.
	 *
	 * @example
	 * ```ts
	 * {
	 *   refresh: refreshToken
	 * }
	 * ```
	 */
	refresh?: string
	/**
	 * Expected issuer for validation.
	 * @internal
	 */
	issuer?: string
	/**
	 * Expected audience for validation.
	 * @internal
	 */
	audience?: string
	/**
	 * Custom fetch for HTTP requests.
	 */
	fetch?: FetchLike
}

/**
 * Result of successful token verification.
 */
export interface VerifyResult<T extends SubjectSchema> {
	/**
	 * New tokens if access token was refreshed during verification.
	 */
	tokens?: Tokens
	/**
	 * Audience (client ID) the token was issued for.
	 * @internal
	 */
	aud: string
	/**
	 * Decoded subject information from the access token.
	 *
	 * Contains user data that was encoded when the token was issued.
	 */
	subject: {
		[type in keyof T]: {
			type: type
			properties: T[type] extends StandardSchemaV1<unknown, infer Output> ? Output : unknown
		}
	}[keyof T]
	/**
	 * OAuth 2.0 scopes granted for this token.
	 */
	scopes?: string[]
}

/**
 * Options for credentials authentication.
 */
export interface CredentialsOptions {
	/**
	 * OAuth 2.0 scopes to request for the service.
	 *
	 * @example
	 * ```ts
	 * {
	 *   scopes: ["read:users", "write:posts", "admin"]
	 * }
	 * ```
	 */
	scopes?: string[]
	/**
	 * Additional parameters to include in the token request.
	 *
	 * @example
	 * ```ts
	 * {
	 *   params: {
	 *     tenant_id: "tenant-123",
	 *     environment: "production"
	 *   }
	 * }
	 * ```
	 */
	params?: Record<string, string>
}

/**
 * Options for token revocation.
 */
export interface RevokeOptions {
	/**
	 * Revoke all refresh tokens for the user.
	 *
	 * Logs the user out from all devices and applications.
	 *
	 * @default false
	 * @example
	 * ```ts
	 * { all: true }
	 * ```
	 */
	all?: boolean
	/**
	 * Revoke tokens only for a specific client (admin operation).
	 *
	 * @example
	 * ```ts
	 * { clientID: "mobile-app" }
	 * ```
	 */
	clientID?: string
}

/**
 * Options for UserInfo requests.
 */
export interface UserInfoOptions {
	/**
	 * Custom fetch for the UserInfo request.
	 */
	fetch?: FetchLike
}

/**
 * UserInfo response containing user claims.
 */
export interface UserInfoResult {
	/**
	 * User information claims from the UserInfo endpoint.
	 *
	 * Claims depend on scopes requested during authorization.
	 *
	 * @example
	 * ```ts
	 * {
	 *   sub: "user123",
	 *   name: "John Doe",
	 *   email: "john@example.com",
	 *   picture: "https://example.com/avatar.jpg"
	 * }
	 * ```
	 */
	userinfo: Record<string, unknown>
}

/**
 * ID token claims following OpenID Connect specification.
 */
export interface IdTokenClaims {
	/**
	 * Subject identifier - unique user ID.
	 */
	sub: string
	/**
	 * Audience - client ID the token was issued for.
	 */
	aud: string | string[]
	/**
	 * Issuer identifier.
	 */
	iss: string
	/**
	 * Expiration time (seconds since Unix epoch).
	 */
	exp: number
	/**
	 * Issued at time (seconds since Unix epoch).
	 */
	iat: number
	/**
	 * Authentication time (seconds since Unix epoch).
	 */
	auth_time?: number
	/**
	 * Nonce for associating client session with ID token.
	 */
	nonce?: string
	/**
	 * Session ID for session management.
	 */
	sid?: string
	/**
	 * User's full name (profile scope).
	 */
	name?: string
	/**
	 * User's email address (email scope).
	 */
	email?: string
	/**
	 * Whether email has been verified (email scope).
	 */
	email_verified?: boolean
	/**
	 * User's preferred username (profile scope).
	 */
	preferred_username?: string
	/**
	 * URL of user's profile picture (profile scope).
	 */
	picture?: string
}

/**
 * Options for logout flows.
 */
export interface LogoutOptions {
	/**
	 * Previously issued ID token to identify the user session.
	 *
	 * @example
	 * ```ts
	 * {
	 *   idTokenHint: storedIdToken
	 * }
	 * ```
	 */
	idTokenHint?: string
	/**
	 * URI to redirect to after logout.
	 *
	 * Must be pre-registered with the authorization server.
	 *
	 * @example
	 * ```ts
	 * {
	 *   postLogoutRedirectUri: "https://myapp.com/logged-out"
	 * }
	 * ```
	 */
	postLogoutRedirectUri?: string
	/**
	 * State parameter returned to the post-logout redirect URI.
	 *
	 * @example
	 * ```ts
	 * {
	 *   state: "logout-state-123"
	 * }
	 * ```
	 */
	state?: string
}

/**
 * Draft Auth client with all OAuth and OIDC operations.
 */
export interface Client {
	/**
	 * Start an OAuth authorization flow.
	 *
	 * @param redirectURI - Where users will be sent after authorization
	 * @param response - Response type ("code" or "token")
	 * @param opts - Additional authorization options
	 * @returns Authorization URL and challenge data
	 *
	 * @example Basic flow
	 * ```ts
	 * const result = await client.authorize(
	 *   "https://myapp.com/callback",
	 *   "code"
	 * )
	 * if (result.success) {
	 *   window.location.href = result.data.url
	 * }
	 * ```
	 *
	 * @example PKCE flow
	 * ```ts
	 * const result = await client.authorize(
	 *   "https://spa.example.com/callback",
	 *   "code",
	 *   { pkce: true, scopes: ["openid", "profile"] }
	 * )
	 * if (result.success) {
	 *   sessionStorage.setItem("challenge", JSON.stringify(result.data.challenge))
	 *   window.location.href = result.data.url
	 * }
	 * ```
	 */
	authorize(
		redirectURI: string,
		response: "code" | "token",
		opts?: AuthorizeOptions
	): Promise<Result<AuthorizeResult>>

	/**
	 * Exchange authorization code for tokens.
	 *
	 * @param code - Authorization code from the callback
	 * @param redirectURI - Same redirect URI used in authorization
	 * @param verifier - PKCE code verifier (required for PKCE flows)
	 * @returns Access tokens and metadata
	 *
	 * @example Basic exchange
	 * ```ts
	 * const urlParams = new URLSearchParams(window.location.search)
	 * const code = urlParams.get('code')
	 *
	 * if (code) {
	 *   const result = await client.exchange(code, "https://myapp.com/callback")
	 *   if (result.success) {
	 *     const { access, refresh } = result.data
	 *     // Store tokens securely
	 *   }
	 * }
	 * ```
	 *
	 * @example PKCE exchange
	 * ```ts
	 * const challenge = JSON.parse(sessionStorage.getItem("challenge") || "{}")
	 * const code = new URLSearchParams(window.location.search).get('code')
	 *
	 * if (code && challenge.verifier) {
	 *   const result = await client.exchange(
	 *     code,
	 *     "https://spa.example.com/callback",
	 *     challenge.verifier
	 *   )
	 *   if (result.success) {
	 *     sessionStorage.removeItem("challenge")
	 *     // Handle tokens
	 *   }
	 * }
	 * ```
	 */
	exchange(
		code: string,
		redirectURI: string,
		verifier?: string
	): Promise<Result<Tokens, InvalidAuthorizationCodeError>>

	/**
	 * Refresh an access token using a refresh token.
	 *
	 * @param refresh - Refresh token to use
	 * @param opts - Additional refresh options
	 * @returns New tokens if refresh was needed
	 *
	 * @example Basic refresh
	 * ```ts
	 * const result = await client.refresh(storedRefreshToken)
	 *
	 * if (result.success && result.data.tokens) {
	 *   const { access, refresh: newRefresh } = result.data.tokens
	 *   updateStoredTokens(access, newRefresh)
	 * } else if (result.success) {
	 *   // Token still valid
	 * } else {
	 *   redirectToLogin()
	 * }
	 * ```
	 */
	refresh(
		refresh: string,
		opts?: RefreshOptions
	): Promise<Result<{ tokens?: Tokens }, InvalidRefreshTokenError | InvalidAccessTokenError>>

	/**
	 * Verify and decode an access token.
	 *
	 * @param subjects - Subject schema used when creating the issuer
	 * @param token - Access token to verify
	 * @param options - Additional verification options
	 * @returns Decoded token data and user information
	 *
	 * @example Basic verification
	 * ```ts
	 * const result = await client.verify(subjects, accessToken)
	 *
	 * if (result.success) {
	 *   const { subject, scopes } = result.data
	 *   // Access user ID: subject.properties.userID
	 *   // Access scopes: scopes?.join(', ')
	 * }
	 * ```
	 *
	 * @example With automatic refresh
	 * ```ts
	 * const result = await client.verify(subjects, accessToken, {
	 *   refresh: refreshToken
	 * })
	 *
	 * if (result.success) {
	 *   if (result.data.tokens) {
	 *     // Tokens were refreshed
	 *     updateStoredTokens(result.data.tokens.access, result.data.tokens.refresh)
	 *   }
	 *   // Use verified subject data
	 *   const user = result.data.subject.properties
	 * }
	 * ```
	 */
	verify<T extends SubjectSchema>(
		subjects: T,
		token: string,
		options?: VerifyOptions
	): Promise<
		Result<
			VerifyResult<T>,
			InvalidRefreshTokenError | InvalidAccessTokenError | InvalidSubjectError
		>
	>

	/**
	 * Revoke a refresh token to invalidate sessions.
	 *
	 * @param token - Refresh token to revoke
	 * @param opts - Revocation options
	 * @returns Success indicator or error
	 *
	 * @example Single device logout
	 * ```ts
	 * const result = await client.revoke(refreshToken)
	 * if (result.success) {
	 *   // Successfully logged out from this device
	 *   clearStoredTokens()
	 * }
	 * ```
	 *
	 * @example Global logout
	 * ```ts
	 * const result = await client.revoke(refreshToken, { all: true })
	 * if (result.success) {
	 *   // Successfully logged out from all devices
	 *   redirectToLogin()
	 * }
	 * ```
	 */
	revoke(
		token: string,
		opts?: RevokeOptions
	): Promise<Result<void, UnsupportedTokenTypeError | TokenRevocationError>>

	/**
	 * Fetch user information from the UserInfo endpoint.
	 *
	 * @param accessToken - Valid access token with appropriate scopes
	 * @param opts - UserInfo request options
	 * @returns User claims from the UserInfo endpoint
	 *
	 * @example Basic UserInfo request
	 * ```ts
	 * const result = await client.userinfo(accessToken)
	 *
	 * if (result.success) {
	 *   const { userinfo } = result.data
	 *   // Access name: userinfo.name
	 *   // Access email: userinfo.email
	 * }
	 * ```
	 */
	userinfo(
		accessToken: string,
		opts?: UserInfoOptions
	): Promise<Result<UserInfoResult, InvalidAccessTokenError>>

	/**
	 * Verify and decode an OIDC ID token.
	 *
	 * @param idToken - ID token to verify
	 * @returns Verified ID token claims
	 *
	 * @example ID token verification
	 * ```ts
	 * const result = await client.verifyIdToken(idToken)
	 *
	 * if (result.success) {
	 *   const { claims } = result.data
	 *   // Access user ID: claims.sub
	 *   // Access email: claims.email
	 * }
	 * ```
	 */
	verifyIdToken(
		idToken: string
	): Promise<Result<{ claims: IdTokenClaims }, InvalidAccessTokenError>>

	/**
	 * Authenticate using OAuth 2.0 client credentials flow.
	 * This method is used for machine-to-machine authentication.
	 *
	 * @param opts - Credentials options
	 * @returns Access tokens for service authentication
	 *
	 * @example Basic service authentication
	 * ```ts
	 * const client = createClient({
	 *   clientID: "api-service-1",
	 *   clientSecret: "super-secret-key",
	 *   issuer: "https://auth.mycompany.com"
	 * })
	 *
	 * const result = await client.credentials({
	 *   scopes: ["read:users", "write:posts"]
	 * })
	 *
	 * if (result.success) {
	 *   const { access } = result.data
	 *   // Use access token for API calls
	 *   const response = await fetch('/api/users', {
	 *     headers: { Authorization: `Bearer ${access}` }
	 *   })
	 * }
	 * ```
	 *
	 * @example Multi-tenant service
	 * ```ts
	 * const result = await client.credentials({
	 *   scopes: ["tenant:read", "tenant:write"],
	 *   params: {
	 *     tenant_id: "tenant-123",
	 *     environment: "production"
	 *   }
	 * })
	 * ```
	 */
	credentials(
		opts?: CredentialsOptions
	): Promise<Result<Tokens, InvalidAuthorizationCodeError>>

	/**
	 * Generate a logout URL for ending user sessions.
	 *
	 * @param opts - Logout options
	 * @returns Logout URL to redirect the user to
	 *
	 * @example Basic logout
	 * ```ts
	 * const logoutUrl = await client.logout()
	 * window.location.href = logoutUrl
	 * ```
	 *
	 * @example Logout with redirect
	 * ```ts
	 * const logoutUrl = await client.logout({
	 *   postLogoutRedirectUri: "https://myapp.com/goodbye",
	 *   state: "logout-completed"
	 * })
	 * window.location.href = logoutUrl
	 * ```
	 */
	logout(opts?: LogoutOptions): Promise<string>
}

/**
 * Create a Draft Auth client.
 *
 * @param input - Client configuration
 * @returns Configured client instance
 *
 * @example Basic setup
 * ```ts
 * const client = createClient({
 *   clientID: "my-web-app",
 *   issuer: "https://auth.mycompany.com"
 * })
 * ```
 */
export const createClient = (input: ClientInput): Client => {
	const jwksCache = new Map<string, ReturnType<typeof createLocalJWKSet>>()
	const issuerCache = new Map<string, WellKnown>()
	const issuer = input.issuer || process.env.DRAFTAUTH_ISSUER
	if (!issuer) throw new Error("No issuer configured")
	const f = input.fetch ?? (fetch as FetchLike)

	const getIssuer = async (): Promise<WellKnown> => {
		const cached = issuerCache.get(issuer)
		if (cached) return cached

		// Try OIDC discovery first
		try {
			const oidcDiscovery = (await f(`${issuer}/.well-known/openid-configuration`).then(
				(r: FetchResponse) => r.json()
			)) as WellKnown

			if (oidcDiscovery.authorization_endpoint) {
				issuerCache.set(issuer, oidcDiscovery)
				return oidcDiscovery
			}
		} catch {}

		// Fallback to OAuth 2.0 Authorization Server Metadata
		const wellKnown = (await f(`${issuer}/.well-known/oauth-authorization-server`).then(
			(r: FetchResponse) => r.json()
		)) as WellKnown
		issuerCache.set(issuer, wellKnown)
		return wellKnown
	}

	const getJWKS = async () => {
		const wk = await getIssuer()
		const cached = jwksCache.get(issuer!)
		if (cached) return cached
		const keyset = (await f(wk.jwks_uri).then((r: FetchResponse) => r.json())) as JSONWebKeySet
		const result = createLocalJWKSet(keyset)
		jwksCache.set(issuer!, result)
		return result
	}

	const client: Client = {
		async authorize(
			redirectURI: string,
			response: "code" | "token",
			opts?: AuthorizeOptions
		): Promise<Result<AuthorizeResult>> {
			try {
				const wk = await getIssuer()
				const authUrl = new URL(wk.authorization_endpoint)
				const challenge: Challenge = {
					state: crypto.randomUUID()
				}

				authUrl.searchParams.set("client_id", input.clientID)
				authUrl.searchParams.set("redirect_uri", redirectURI)
				authUrl.searchParams.set("response_type", response)
				authUrl.searchParams.set("state", challenge.state)

				if (opts?.provider) authUrl.searchParams.set("provider", opts.provider)
				if (opts?.scopes) authUrl.searchParams.set("scope", opts.scopes.join(" "))
				if (opts?.nonce) authUrl.searchParams.set("nonce", opts.nonce)
				if (opts?.prompt) authUrl.searchParams.set("prompt", opts.prompt)
				if (opts?.maxAge) authUrl.searchParams.set("max_age", opts.maxAge.toString())
				if (opts?.idTokenHint) authUrl.searchParams.set("id_token_hint", opts.idTokenHint)
				if (opts?.loginHint) authUrl.searchParams.set("login_hint", opts.loginHint)

				if (opts?.pkce && response === "code") {
					const pkce = await generatePKCE()
					authUrl.searchParams.set("code_challenge_method", "S256")
					authUrl.searchParams.set("code_challenge", pkce.challenge)
					challenge.verifier = pkce.verifier
				}

				return {
					success: true,
					data: {
						challenge,
						url: authUrl.toString()
					}
				}
			} catch (error) {
				return { success: false, error: error as Error }
			}
		},

		async exchange(
			code: string,
			redirectURI: string,
			verifier?: string
		): Promise<Result<Tokens, InvalidAuthorizationCodeError>> {
			try {
				const wk = await getIssuer()
				const response = await f(wk.token_endpoint, {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded"
					},
					body: new URLSearchParams({
						code,
						redirect_uri: redirectURI,
						grant_type: "authorization_code",
						client_id: input.clientID,
						...(verifier ? { code_verifier: verifier } : {})
					}).toString()
				})

				if (!response.ok) {
					return {
						success: false,
						error: new InvalidAuthorizationCodeError()
					}
				}

				const responseText = await response.text()
				let json: unknown
				try {
					json = JSON.parse(responseText)
				} catch {
					return {
						success: false,
						error: new InvalidAuthorizationCodeError()
					}
				}

				const tokenResponse = json as TokenResponse
				return {
					success: true,
					data: {
						access: tokenResponse.access_token,
						refresh: tokenResponse.refresh_token,
						expiresIn: tokenResponse.expires_in,
						...(tokenResponse.id_token && { idToken: tokenResponse.id_token }),
						...(tokenResponse.scope && { scope: tokenResponse.scope })
					}
				}
			} catch {
				return {
					success: false,
					error: new InvalidAuthorizationCodeError()
				}
			}
		},

		async refresh(
			refresh: string,
			opts?: RefreshOptions
		): Promise<
			Result<{ tokens?: Tokens }, InvalidRefreshTokenError | InvalidAccessTokenError>
		> {
			try {
				if (opts?.access) {
					try {
						const jwks = await getJWKS()
						await jwtVerify(opts.access, jwks, { issuer })

						return { success: true, data: {} }
					} catch {}
				}

				const wk = await getIssuer()
				const response = await f(wk.token_endpoint, {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded"
					},
					body: new URLSearchParams({
						refresh_token: refresh,
						grant_type: "refresh_token",
						client_id: input.clientID
					}).toString()
				})

				if (!response.ok) {
					return {
						success: false,
						error: new InvalidRefreshTokenError()
					}
				}

				const tokenResponse = (await response.json()) as TokenResponse
				return {
					success: true,
					data: {
						tokens: {
							access: tokenResponse.access_token,
							refresh: tokenResponse.refresh_token,
							expiresIn: tokenResponse.expires_in,
							...(tokenResponse.id_token && { idToken: tokenResponse.id_token }),
							...(tokenResponse.scope && { scope: tokenResponse.scope })
						}
					}
				}
			} catch {
				return {
					success: false,
					error: new InvalidRefreshTokenError()
				}
			}
		},

		async verify<T extends SubjectSchema>(
			subjects: T,
			token: string,
			options?: VerifyOptions
		): Promise<
			Result<
				VerifyResult<T>,
				InvalidRefreshTokenError | InvalidAccessTokenError | InvalidSubjectError
			>
		> {
			try {
				const jwks = await getJWKS()
				const jwtResult = await jwtVerify(token, jwks, { issuer })

				if (jwtResult.payload.mode !== "access") {
					return {
						success: false,
						error: new InvalidAccessTokenError()
					}
				}

				const subjectType = jwtResult.payload.type as keyof T
				if (subjectType && subjects[subjectType]) {
					return {
						success: true,
						data: {
							aud: jwtResult.payload.aud as string,
							subject: {
								type: subjectType,
								properties: jwtResult.payload.properties
							} as VerifyResult<T>["subject"],
							...(jwtResult.payload.scopes
								? { scopes: jwtResult.payload.scopes as string[] }
								: {})
						}
					}
				}

				return {
					success: false,
					error: new InvalidSubjectError()
				}
			} catch (e) {
				if (e instanceof errors.JWTExpired && options?.refresh) {
					const refreshed = await client.refresh(options.refresh)
					if (!refreshed.success)
						return refreshed as Result<
							VerifyResult<T>,
							InvalidRefreshTokenError | InvalidAccessTokenError | InvalidSubjectError
						>

					if (!refreshed.data.tokens) {
						return {
							success: false,
							error: new InvalidAccessTokenError()
						}
					}

					const verified = await client.verify(subjects, refreshed.data.tokens.access, {
						refresh: refreshed.data.tokens.refresh,
						issuer: options?.issuer,
						audience: options?.audience,
						fetch: options?.fetch
					})

					if (!verified.success) return verified

					return {
						success: true,
						data: {
							...verified.data,
							tokens: refreshed.data.tokens
						}
					}
				}
				return {
					success: false,
					error: new InvalidAccessTokenError()
				}
			}
		},

		async revoke(
			token: string,
			opts?: RevokeOptions
		): Promise<Result<void, UnsupportedTokenTypeError | TokenRevocationError>> {
			try {
				const wk = await getIssuer()
				const revokeEndpoint = wk.revocation_endpoint ?? `${issuer}/revoke`

				const response = await f(revokeEndpoint, {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded"
					},
					body: new URLSearchParams({
						token: token,
						token_type_hint: "refresh_token",
						...(opts?.all ? { revoke_all: "true" } : {}),
						...(opts?.clientID ? { client_id: opts.clientID } : {})
					}).toString()
				})

				if (!response.ok) {
					const errorText = await response.text()
					try {
						const errorJson = JSON.parse(errorText) as {
							error?: string
							error_description?: string
						}
						if (errorJson.error === "unsupported_token_type") {
							return { success: false, error: new UnsupportedTokenTypeError() }
						}
					} catch {}

					return {
						success: false,
						error: new TokenRevocationError(`Revocation failed: ${errorText}`)
					}
				}

				return { success: true, data: undefined }
			} catch (error) {
				return {
					success: false,
					error: new TokenRevocationError(`Revocation error: ${error}`)
				}
			}
		},

		async userinfo(
			accessToken: string,
			opts?: UserInfoOptions
		): Promise<Result<UserInfoResult, InvalidAccessTokenError>> {
			try {
				const wk = await getIssuer()
				if (!wk.userinfo_endpoint) {
					return { success: false, error: new InvalidAccessTokenError() }
				}

				const fetchFn = opts?.fetch ?? f
				const response = await fetchFn(wk.userinfo_endpoint, {
					headers: {
						Authorization: `Bearer ${accessToken}`
					}
				})

				if (!response.ok) {
					return { success: false, error: new InvalidAccessTokenError() }
				}

				const userinfo = (await response.json()) as Record<string, unknown>
				return { success: true, data: { userinfo } }
			} catch {
				return { success: false, error: new InvalidAccessTokenError() }
			}
		},

		async verifyIdToken(
			idToken: string
		): Promise<Result<{ claims: IdTokenClaims }, InvalidAccessTokenError>> {
			try {
				const jwks = await getJWKS()
				const verifyResult = await jwtVerify<IdTokenClaims>(idToken, jwks, { issuer })
				return { success: true, data: { claims: verifyResult.payload } }
			} catch {
				return { success: false, error: new InvalidAccessTokenError() }
			}
		},

		async credentials(
			opts?: CredentialsOptions
		): Promise<Result<Tokens, InvalidAuthorizationCodeError>> {
			try {
				if (!input.clientSecret) {
					return {
						success: false,
						error: new InvalidAuthorizationCodeError()
					}
				}

				const wk = await getIssuer()
				const requestBody = new URLSearchParams({
					grant_type: "client_credentials",
					provider: "client-credentials", // Use our standard provider name
					...(opts?.scopes && { scope: opts.scopes.join(" ") }),
					...(opts?.params || {})
				})

				// Use client_secret_basic authentication (recommended)
				const credentials = btoa(`${input.clientID}:${input.clientSecret}`)

				const response = await f(wk.token_endpoint, {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
						Authorization: `Basic ${credentials}`
					},
					body: requestBody.toString()
				})

				if (!response.ok) {
					return {
						success: false,
						error: new InvalidAuthorizationCodeError()
					}
				}

				const tokenResponse = (await response.json()) as TokenResponse
				return {
					success: true,
					data: {
						access: tokenResponse.access_token,
						refresh: tokenResponse.refresh_token,
						expiresIn: tokenResponse.expires_in,
						...(tokenResponse.id_token && { idToken: tokenResponse.id_token }),
						...(tokenResponse.scope && { scope: tokenResponse.scope })
					}
				}
			} catch (error) {
				return {
					success: false,
					error: new InvalidAuthorizationCodeError()
				}
			}
		},

		async logout(opts?: LogoutOptions): Promise<string> {
			const wk = await getIssuer()
			const logoutUrl = new URL(wk.end_session_endpoint ?? `${issuer}/logout`)

			if (opts?.idTokenHint) {
				logoutUrl.searchParams.set("id_token_hint", opts.idTokenHint)
			}

			if (opts?.postLogoutRedirectUri) {
				logoutUrl.searchParams.set("post_logout_redirect_uri", opts.postLogoutRedirectUri)
			}

			if (opts?.state) {
				logoutUrl.searchParams.set("state", opts.state)
			}

			return logoutUrl.toString()
		}
	}

	return client
}
