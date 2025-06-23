/**
 * Shared type definitions for Draft Auth core.
 * Contains only types that are used across multiple modules to avoid duplication.
 */

/**
 * Enhanced authorization state with OIDC parameters.
 * Used throughout OAuth 2.0 and OIDC authorization flows.
 */
export interface AuthorizationState {
	/** OAuth 2.0 redirect URI */
	redirect_uri?: string
	/** OAuth 2.0 response type (code, token, id_token, etc.) */
	response_type?: string
	/** OAuth 2.0 state parameter for CSRF protection */
	state?: string
	/** OAuth 2.0 client identifier */
	client_id?: string
	/** OAuth 2.0 audience parameter */
	audience?: string
	/** Raw scope string from request */
	scope?: string
	/** OIDC nonce for ID token binding */
	nonce?: string
	/** OIDC prompt parameter controlling authentication behavior */
	prompt?: string
	/** OIDC max_age parameter for authentication time validation */
	max_age?: number
	/** OIDC id_token_hint for logout flows */
	id_token_hint?: string
	/** OIDC login_hint for prefilling username */
	login_hint?: string
	/** Parsed OAuth 2.0 scopes array */
	scopes?: string[]
	/** PKCE challenge data for code verification */
	pkce?: {
		challenge: string
		method: "S256"
	}
}

/**
 * Token generation result with OIDC support.
 * Used by token generation functions across multiple handlers.
 */
export interface TokenGenerationResult {
	/** OAuth 2.0 access token */
	access: string
	/** Token expiration time in seconds */
	expiresIn: number
	/** OAuth 2.0 refresh token */
	refresh: string
	/** OIDC ID token (optional) */
	id_token?: string
}

/**
 * Code storage payload for authorization code grant.
 * Used for storing authorization code data during OAuth flows.
 */
export interface CodeStoragePayload {
	/** Subject type identifier */
	type: string
	/** Subject properties/claims */
	properties: unknown
	/** Resolved subject identifier for JWT */
	subject: string
	/** Redirect URI used in authorization request */
	redirectURI: string
	/** Client identifier */
	clientID: string
	/** OAuth 2.0 scopes */
	scopes?: string[]
	/** OIDC nonce for ID token binding */
	nonce?: string
	/** SSO session identifier */
	sessionId?: string
	/** OIDC authentication time */
	authTime?: number
	/** Token TTL configuration */
	ttl: {
		access: number
		refresh: number
	}
	/** PKCE challenge data */
	pkce?: {
		challenge: string
		method: "S256"
	}
}
