/**
 * Use the Draft Auth client kick off your OAuth flows, exchange tokens, refresh tokens,
 * and verify tokens.
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
 * Kick off the OAuth flow by calling `authorize`.
 *
 * ```ts
 * const redirect_uri = "https://myserver.com/callback"
 *
 * const { url } = await client.authorize(
 *   redirect_uri,
 *   "code"
 * )
 * ```
 *
 * When the user completes the flow, `exchange` the code for tokens.
 *
 * ```ts
 * const tokens = await client.exchange(query.get("code"), redirect_uri)
 * ```
 *
 * And `verify` the tokens.
 *
 * ```ts
 * const verified = await client.verify(subjects, tokens.access)
 * ```
 *
 * @packageDocumentation
 */
import { type JSONWebKeySet, createLocalJWKSet, decodeJwt, errors, jwtVerify } from "jose"
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
 * The well-known information for an OAuth 2.0 authorization server.
 * @internal
 */
export interface WellKnown {
	/**
	 * The URI to the JWKS endpoint.
	 */
	jwks_uri: string
	/**
	 * The URI to the token endpoint.
	 */
	token_endpoint: string
	/**
	 * The URI to the authorization endpoint.
	 */
	authorization_endpoint: string
}

/**
 * Enhanced OIDC discovery information following OpenID Connect Discovery 1.0 specification.
 * @internal
 */
export interface OidcDiscovery extends WellKnown {
	/**
	 * The issuer identifier.
	 */
	issuer: string
	/**
	 * The URI to the UserInfo endpoint.
	 */
	userinfo_endpoint?: string
	/**
	 * The URI to the logout endpoint.
	 */
	end_session_endpoint?: string
	/**
	 * The URI to the token revocation endpoint.
	 */
	revocation_endpoint?: string
	/**
	 * Array of supported OAuth 2.0 scope values.
	 */
	scopes_supported?: string[]
	/**
	 * Array of supported claims.
	 */
	claims_supported?: string[]
	/**
	 * Array of supported response types.
	 */
	response_types_supported?: string[]
	/**
	 * Array of supported grant types.
	 */
	grant_types_supported?: string[]
	/**
	 * Array of supported subject types.
	 */
	subject_types_supported?: string[]
	/**
	 * Array of supported ID token signing algorithms.
	 */
	id_token_signing_alg_values_supported?: string[]
	/**
	 * Array of supported response modes.
	 */
	response_modes_supported?: string[]
	/**
	 * Array of supported token endpoint authentication methods.
	 */
	token_endpoint_auth_methods_supported?: string[]
	/**
	 * Boolean indicating if claims parameter is supported.
	 */
	claims_parameter_supported?: boolean
	/**
	 * Boolean indicating if request parameter is supported.
	 */
	request_parameter_supported?: boolean
	/**
	 * Boolean indicating if request_uri parameter is supported.
	 */
	request_uri_parameter_supported?: boolean
	/**
	 * Boolean indicating if request_uri registration is required.
	 */
	require_request_uri_registration?: boolean
	/**
	 * Array of supported revocation endpoint authentication methods.
	 */
	revocation_endpoint_auth_methods_supported?: string[]
}

/**
 * The tokens returned by the auth server.
 */
export interface Tokens {
	/**
	 * The access token.
	 */
	access: string
	/**
	 * The refresh token.
	 */
	refresh: string
	/**
	 * The number of seconds until the access token expires.
	 */
	expiresIn: number
	/**
	 * The OIDC ID token (when openid scope is requested).
	 */
	idToken?: string
	/**
	 * The granted scopes as a space-separated string.
	 */
	scope?: string
}

/**
 * The challenge that you can use to verify the code.
 */
export type Challenge = {
	/**
	 * The state that was sent to the redirect URI.
	 */
	state: string
	/**
	 * The verifier that was sent to the redirect URI.
	 */
	verifier?: string
}

/**
 * Configure the client.
 */
export interface ClientInput {
	/**
	 * The client ID. This is just a string to identify your app.
	 *
	 * If you have a web app and a mobile app, you want to use different client IDs both.
	 *
	 * @example
	 * ```ts
	 * {
	 *   clientID: "my-client"
	 * }
	 * ```
	 */
	clientID: string
	/**
	 * The URL of your Draft Auth server.
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
	 * Optionally, override the internally used fetch function.
	 *
	 * This is useful if you are using a polyfilled fetch function in your application and you
	 * want the client to use it too.
	 */
	fetch?: FetchLike
}

export interface AuthorizeOptions {
	/**
	 * Enable the PKCE flow. This is for SPA apps.
	 *
	 * ```ts
	 * {
	 *   pkce: true
	 * }
	 * ```
	 *
	 * @default false
	 */
	pkce?: boolean
	/**
	 * The provider you want to use for the OAuth flow.
	 *
	 * ```ts
	 * {
	 *   provider: "google"
	 * }
	 * ```
	 *
	 * If no provider is specified, the user is directed to a page where they can select from the
	 * list of configured providers.
	 *
	 * If there's only one provider configured, the user will be redirected to that.
	 */
	provider?: string
	/**
	 * The scopes you want to request.
	 *
	 * @example
	 * ```ts
	 * {
	 *  scopes: ["read", "write"]
	 * }
	 * ```
	 */
	scopes?: string[]
	/**
	 * OIDC nonce parameter for preventing replay attacks in ID tokens.
	 * Required when using implicit flow with ID token.
	 *
	 * @example
	 * ```ts
	 * {
	 *   nonce: "random-nonce-value"
	 * }
	 * ```
	 */
	nonce?: string
	/**
	 * OIDC prompt parameter controlling authentication behavior.
	 *
	 * - `none`: No authentication or consent UI should be displayed
	 * - `login`: Force user to re-authenticate
	 * - `consent`: Force user to grant consent again
	 * - `select_account`: Prompt user to select an account
	 *
	 * @example
	 * ```ts
	 * {
	 *   prompt: "login"
	 * }
	 * ```
	 */
	prompt?: "none" | "login" | "consent" | "select_account"
	/**
	 * Maximum authentication age in seconds.
	 * If the user's authentication is older than this, they will be prompted to re-authenticate.
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
	 * Preferred user interface locales for authentication.
	 * Space-separated list of BCP47 language tags.
	 *
	 * @example
	 * ```ts
	 * {
	 *   uiLocales: "en-US es-ES"
	 * }
	 * ```
	 */
	uiLocales?: string
	/**
	 * ID token hint for logout flows or user identification.
	 * Previously issued ID token that can help identify the user.
	 *
	 * @example
	 * ```ts
	 * {
	 *   idTokenHint: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
	 * }
	 * ```
	 */
	idTokenHint?: string
	/**
	 * Login hint to pre-fill the username field.
	 * Can be an email address or username.
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

export interface AuthorizeResult {
	/**
	 * The challenge that you can use to verify the code. This is for the PKCE flow for SPA apps.
	 *
	 * This is an object that you _stringify_ and store it in session storage.
	 *
	 * ```ts
	 * sessionStorage.setItem("challenge", JSON.stringify(challenge))
	 * ```
	 */
	challenge: Challenge
	/**
	 * The URL to redirect the user to. This starts the OAuth flow.
	 *
	 * For example, for SPA apps.
	 *
	 * ```ts
	 * location.href = url
	 * ```
	 */
	url: string
}

/**
 * Returned when the exchange is successful.
 */
export interface ExchangeSuccess {
	/**
	 * This is always `false` when the exchange is successful.
	 */
	err: false
	/**
	 * The access and refresh tokens.
	 */
	tokens: Tokens
}

/**
 * Returned when the exchange fails.
 */
export interface ExchangeError {
	/**
	 * The type of error that occurred. You can handle this by checking the type.
	 *
	 * @example
	 * ```ts
	 * import { InvalidAuthorizationCodeError } from "@draftauth/core/error"
	 *
	 * console.log(err instanceof InvalidAuthorizationCodeError)
	 *```
	 */
	err: InvalidAuthorizationCodeError
}

export interface RefreshOptions {
	/**
	 * Optionally, pass in the access token.
	 */
	access?: string
}

/**
 * Returned when the refresh is successful.
 */
export interface RefreshSuccess {
	/**
	 * This is always `false` when the refresh is successful.
	 */
	err: false
	/**
	 * Returns the refreshed tokens only if they've been refreshed.
	 *
	 * If they are still valid, this will be `undefined`.
	 */
	tokens?: Tokens
}

/**
 * Returned when the refresh fails.
 */
export interface RefreshError {
	/**
	 * The type of error that occurred. You can handle this by checking the type.
	 *
	 * @example
	 * ```ts
	 * import { InvalidRefreshTokenError } from "@draftauth/core/error"
	 *
	 * console.log(err instanceof InvalidRefreshTokenError)
	 *```
	 */
	err: InvalidRefreshTokenError | InvalidAccessTokenError
}

export interface VerifyOptions {
	/**
	 * Optionally, pass in the refresh token.
	 *
	 * If passed in, this will automatically refresh the access token if it has expired.
	 */
	refresh?: string
	/**
	 * @internal
	 */
	issuer?: string
	/**
	 * @internal
	 */
	audience?: string
	/**
	 * Optionally, override the internally used fetch function.
	 *
	 * This is useful if you are using a polyfilled fetch function in your application and you
	 * want the client to use it too.
	 */
	fetch?: FetchLike
}

export interface VerifyResult<T extends SubjectSchema> {
	/**
	 * This is always `undefined` when the verify is successful.
	 */
	err?: undefined
	/**
	 * Returns the refreshed tokens only if they've been refreshed.
	 *
	 * If they are still valid, this will be undefined.
	 */
	tokens?: Tokens
	/**
	 * @internal
	 */
	aud: string
	/**
	 * The decoded subjects from the access token.
	 *
	 * Has the same shape as the subjects you defined when creating the issuer.
	 */
	subject: {
		[type in keyof T]: { type: type; properties: StandardSchemaV1.InferOutput<T[type]> }
	}[keyof T]
	/**
	 * The scopes of the token.
	 */
	scopes?: string[]
}

/**
 * Returned when the verify call fails.
 */
export interface VerifyError {
	/**
	 * The type of error that occurred. You can handle this by checking the type.
	 *
	 * @example
	 * ```ts
	 * import { InvalidRefreshTokenError } from "@draftauth/core/error"
	 *
	 * console.log(err instanceof InvalidRefreshTokenError)
	 *```
	 */
	err: InvalidRefreshTokenError | InvalidAccessTokenError
}

export interface RevokeOptions {
	/**
	 * Revoke all refresh tokens for the subject.
	 *
	 * When set to `true`, all refresh tokens for the subject will be revoked,
	 * effectively logging the user out from all devices/sessions.
	 *
	 * @example
	 * ```ts
	 * // Revoke all tokens for the user
	 * await client.revoke(refreshToken, { all: true })
	 * ```
	 */
	all?: boolean
	/**
	 * The client ID to revoke tokens for (admin operation).
	 *
	 * When specified, only tokens issued for this specific client will be revoked.
	 * This is useful for admin operations to revoke tokens for a specific application.
	 *
	 * @example
	 * ```ts
	 * // Revoke tokens only for a specific client
	 * await client.revoke(refreshToken, { clientID: "mobile-app" })
	 * ```
	 */
	clientID?: string
}

/**
 * Returned when token revocation is successful.
 */
export interface RevokeSuccess {
	/**
	 * This is always `false` when the revocation is successful.
	 */
	err: false
}

/**
 * Returned when token revocation fails.
 */
export interface RevokeError {
	/**
	 * The type of error that occurred during revocation.
	 *
	 * @example
	 * ```ts
	 * import { UnsupportedTokenTypeError } from "@draftauth/core/error"
	 *
	 * if (result.err instanceof UnsupportedTokenTypeError) {
	 *   // Token type is not supported for revocation
	 * }
	 * ```
	 */
	err: UnsupportedTokenTypeError | TokenRevocationError
}

/**
 * OIDC UserInfo endpoint options.
 */
export interface UserInfoOptions {
	/**
	 * Optionally, override the internally used fetch function.
	 */
	fetch?: FetchLike
}

/**
 * Successful UserInfo response containing user claims.
 */
export interface UserInfoResult {
	/**
	 * This is always `undefined` when UserInfo request is successful.
	 */
	err?: undefined
	/**
	 * User information claims returned by the UserInfo endpoint.
	 * The claims included depend on the scopes requested during authorization.
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
 * UserInfo request error.
 */
export interface UserInfoError {
	/**
	 * Error that occurred during UserInfo request.
	 */
	err: InvalidAccessTokenError
}

/**
 * OIDC ID token claims following OpenID Connect Core 1.0 specification.
 */
export interface IdTokenClaims {
	/**
	 * Subject identifier - unique identifier for the user.
	 */
	sub: string
	/**
	 * Audience - client ID for which the token was issued.
	 */
	aud: string | string[]
	/**
	 * Issuer identifier.
	 */
	iss: string
	/**
	 * Expiration time (seconds since epoch).
	 */
	exp: number
	/**
	 * Issued at time (seconds since epoch).
	 */
	iat: number
	/**
	 * Authentication time (seconds since epoch).
	 */
	auth_time?: number
	/**
	 * Nonce value used to associate client session with ID token.
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
	 * Whether the email has been verified (email scope).
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
 * Successful ID token verification result.
 */
export interface IdTokenVerifyResult {
	/**
	 * This is always `undefined` when ID token verification is successful.
	 */
	err?: undefined
	/**
	 * The verified ID token claims.
	 */
	claims: IdTokenClaims
}

/**
 * ID token verification error.
 */
export interface IdTokenVerifyError {
	/**
	 * Error that occurred during ID token verification.
	 */
	err: InvalidAccessTokenError
}

/**
 * OIDC logout options following RP-Initiated Logout specification.
 */
export interface LogoutOptions {
	/**
	 * Previously issued ID token to identify the user session.
	 * This helps the authorization server identify which session to terminate.
	 *
	 * @example
	 * ```ts
	 * {
	 *   idTokenHint: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
	 * }
	 * ```
	 */
	idTokenHint?: string
	/**
	 * URI to redirect to after logout.
	 * Must be registered with the authorization server.
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
	 * State parameter for logout request.
	 * Will be returned to the post-logout redirect URI.
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
 * An instance of the Draft Auth client contains the following methods.
 */
export interface Client {
	/**
	 * Start the autorization flow. For example, in SSR sites.
	 *
	 * ```ts
	 * const { url } = await client.authorize(<redirect_uri>, "code")
	 * ```
	 *
	 * This takes a redirect URI and the type of flow you want to use. The redirect URI is the
	 * location where the user will be redirected to after the flow is complete.
	 *
	 * Supports both the _code_ and _token_ flows. We recommend using the _code_ flow as it's more
	 * secure.
	 *
	 * :::tip
	 * This returns a URL to redirect the user to. This starts the OAuth flow.
	 * :::
	 *
	 * This returns a URL to the auth server. You can redirect the user to the URL to start the
	 * OAuth flow.
	 *
	 * For SPA apps, we recommend using the PKCE flow.
	 *
	 * ```ts {4}
	 * const { challenge, url } = await client.authorize(
	 *   <redirect_uri>,
	 *   "code",
	 *   { pkce: true }
	 * )
	 * ```
	 *
	 * This returns a redirect URL and a challenge that you need to use later to verify the code.
	 *
	 * Enhanced OIDC support with additional parameters:
	 *
	 * ```ts
	 * const { challenge, url } = await client.authorize(
	 *   "https://myapp.com/callback",
	 *   "code",
	 *   {
	 *     pkce: true,
	 *     scopes: ["openid", "profile", "email"],
	 *     nonce: "random-nonce",
	 *     prompt: "login",
	 *     maxAge: 3600
	 *   }
	 * )
	 * ```
	 */
	authorize(
		redirectURI: string,
		response: "code" | "token",
		opts?: AuthorizeOptions
	): Promise<AuthorizeResult>

	/**
	 * Exchange the code for access and refresh tokens.
	 *
	 * ```ts
	 * const exchanged = await client.exchange(<code>, <redirect_uri>)
	 * ```
	 *
	 * You call this after the user has been redirected back to your app after the OAuth flow.
	 *
	 * :::tip
	 * For SSR sites, the code is returned in the query parameter.
	 * :::
	 *
	 * So the code comes from the query parameter in the redirect URI. The redirect URI here is
	 * the one that you passed in to the `authorize` call when starting the flow.
	 *
	 * :::tip
	 * For SPA sites, the code is returned through the URL hash.
	 * :::
	 *
	 * If you used the PKCE flow for an SPA app, the code is returned as a part of the redirect URL
	 * hash.
	 *
	 * ```ts {4}
	 * const exchanged = await client.exchange(
	 *   <code>,
	 *   <redirect_uri>,
	 *   <challenge.verifier>
	 * )
	 * ```
	 *
	 * You also need to pass in the previously stored challenge verifier.
	 *
	 * This method returns the access and refresh tokens. Or if it fails, it returns an error that
	 * you can handle depending on the error.
	 *
	 * ```ts
	 * import { InvalidAuthorizationCodeError } from "@draftauth/core/error"
	 *
	 * if (exchanged.err) {
	 *   if (exchanged.err instanceof InvalidAuthorizationCodeError) {
	 *     // handle invalid code error
	 *   }
	 *   else {
	 *     // handle other errors
	 *   }
	 * }
	 *
	 * const { access, refresh, idToken } = exchanged.tokens
	 * ```
	 *
	 * The response now includes ID tokens when the `openid` scope was requested.
	 */
	exchange(
		code: string,
		redirectURI: string,
		verifier?: string
	): Promise<ExchangeSuccess | ExchangeError>

	/**
	 * Refreshes the tokens if they have expired. This is used in an SPA app to maintain the
	 * session, without logging the user out.
	 *
	 * ```ts
	 * const next = await client.refresh(<refresh_token>)
	 * ```
	 *
	 * Can optionally take the access token as well. If passed in, this will skip the refresh
	 * if the access token is still valid.
	 *
	 * ```ts
	 * const next = await client.refresh(<refresh_token>, { access: <access_token> })
	 * ```
	 *
	 * This returns the refreshed tokens only if they've been refreshed.
	 *
	 * ```ts
	 * if (!next.err) {
	 *   // tokens are still valid
	 * }
	 * if (next.tokens) {
	 *   const { access, refresh, idToken } = next.tokens
	 * }
	 * ```
	 *
	 * Or if it fails, it returns an error that you can handle depending on the error.
	 *
	 * ```ts
	 * import { InvalidRefreshTokenError } from "@draftauth/core/error"
	 *
	 * if (next.err) {
	 *   if (next.err instanceof InvalidRefreshTokenError) {
	 *     // handle invalid refresh token error
	 *   }
	 *   else {
	 *     // handle other errors
	 *   }
	 * }
	 * ```
	 *
	 * The response now includes ID tokens when they were originally requested.
	 */
	refresh(refresh: string, opts?: RefreshOptions): Promise<RefreshSuccess | RefreshError>

	/**
	 * Verify the token in the incoming request.
	 *
	 * This is typically used for SSR sites where the token is stored in an HTTP only cookie. And
	 * is passed to the server on every request.
	 *
	 * ```ts
	 * const verified = await client.verify(<subjects>, <token>)
	 * ```
	 *
	 * This takes the subjects that you had previously defined when creating the issuer.
	 *
	 * :::tip
	 * If the refresh token is passed in, it'll automatically refresh the access token.
	 * :::
	 *
	 * This can optionally take the refresh token as well. If passed in, it'll automatically
	 * refresh the access token if it has expired.
	 *
	 * ```ts
	 * const verified = await client.verify(<subjects>, <token>, { refresh: <refresh_token> })
	 * ```
	 *
	 * This returns the decoded subjects from the access token. And the tokens if they've been
	 * refreshed.
	 *
	 * ```ts
	 * // based on the subjects you defined earlier
	 * console.log(verified.subject.properties.userID)
	 *
	 * if (verified.tokens) {
	 *   const { access, refresh, idToken } = verified.tokens
	 * }
	 * ```
	 *
	 * Or if it fails, it returns an error that you can handle depending on the error.
	 *
	 * ```ts
	 * import { InvalidRefreshTokenError } from "@draftauth/core/error"
	 *
	 * if (verified.err) {
	 *   if (verified.err instanceof InvalidRefreshTokenError) {
	 *     // handle invalid refresh token error
	 *   }
	 *   else {
	 *     // handle other errors
	 *   }
	 * }
	 * ```
	 */
	verify<T extends SubjectSchema>(
		subjects: T,
		token: string,
		options?: VerifyOptions
	): Promise<VerifyResult<T> | VerifyError>

	/**
	 * Revoke a refresh token.
	 *
	 * This method allows you to revoke refresh tokens, which is useful for implementing
	 * logout functionality and managing token lifecycle.
	 *
	 * ```ts
	 * const result = await client.revoke(refreshToken)
	 * ```
	 *
	 * Can optionally revoke all tokens for the subject:
	 *
	 * ```ts
	 * // Revoke all tokens for the user (logout from all devices)
	 * const result = await client.revoke(refreshToken, { all: true })
	 * ```
	 *
	 * Or revoke tokens for a specific client (admin operation):
	 *
	 * ```ts
	 * // Revoke tokens only for a specific client
	 * const result = await client.revoke(refreshToken, { clientID: "mobile-app" })
	 * ```
	 *
	 * Error handling:
	 *
	 * ```ts
	 * import { UnsupportedTokenTypeError, TokenRevocationError } from "@draftauth/core/error"
	 *
	 * const result = await client.revoke(token)
	 * if (result.err) {
	 *   if (result.err instanceof UnsupportedTokenTypeError) {
	 *     // Token type not supported for revocation
	 *   } else if (result.err instanceof TokenRevocationError) {
	 *     // General revocation error
	 *   }
	 * }
	 * ```
	 */
	revoke(token: string, opts?: RevokeOptions): Promise<RevokeSuccess | RevokeError>

	/**
	 * Fetch user information from the OIDC UserInfo endpoint.
	 *
	 * This method calls the UserInfo endpoint to retrieve claims about the authenticated user.
	 * The claims returned depend on the scopes that were requested during authorization.
	 *
	 * ```ts
	 * const result = await client.userinfo(accessToken)
	 * if (!result.err) {
	 *   console.log(result.userinfo.sub) // User ID
	 *   console.log(result.userinfo.name) // Full name (if profile scope)
	 *   console.log(result.userinfo.email) // Email (if email scope)
	 * }
	 * ```
	 *
	 * Error handling:
	 *
	 * ```ts
	 * const result = await client.userinfo(accessToken)
	 * if (result.err) {
	 *   // Invalid or expired access token
	 *   console.error("Failed to fetch user info")
	 * }
	 * ```
	 *
	 * @param accessToken - Valid access token with appropriate scopes
	 * @param opts - Optional configuration
	 * @returns Promise resolving to user information or error
	 */
	userinfo(
		accessToken: string,
		opts?: UserInfoOptions
	): Promise<UserInfoResult | UserInfoError>

	/**
	 * Verify an OIDC ID token.
	 *
	 * This method validates and decodes an ID token issued by the authorization server.
	 * ID tokens contain identity information about the authenticated user.
	 *
	 * ```ts
	 * const result = await client.verifyIdToken(idToken)
	 * if (!result.err) {
	 *   console.log(result.claims.sub) // User ID
	 *   console.log(result.claims.name) // User's name
	 *   console.log(result.claims.auth_time) // When user authenticated
	 * }
	 * ```
	 *
	 * Error handling:
	 *
	 * ```ts
	 * const result = await client.verifyIdToken(idToken)
	 * if (result.err) {
	 *   // Invalid, expired, or tampered ID token
	 *   console.error("ID token verification failed")
	 * }
	 * ```
	 *
	 * @param idToken - The ID token to verify
	 * @returns Promise resolving to verified claims or error
	 */
	verifyIdToken(idToken: string): Promise<IdTokenVerifyResult | IdTokenVerifyError>

	/**
	 * Generate an OIDC logout URL following the RP-Initiated Logout specification.
	 *
	 * This method creates a logout URL that can be used to terminate the user's session
	 * at the authorization server and optionally redirect to a post-logout page.
	 *
	 * ```ts
	 * // Basic logout
	 * const logoutUrl = await client.logout()
	 * window.location.href = logoutUrl
	 * ```
	 *
	 * With ID token hint and redirect:
	 *
	 * ```ts
	 * const logoutUrl = await client.logout({
	 *   idTokenHint: tokens.idToken,
	 *   postLogoutRedirectUri: "https://myapp.com/goodbye",
	 *   state: "logout-state-123"
	 * })
	 * window.location.href = logoutUrl
	 * ```
	 *
	 * @param opts - Optional logout parameters
	 * @returns Promise resolving to the logout URL
	 */
	logout(opts?: LogoutOptions): Promise<string>
}

import type { StandardSchemaV1 } from "@standard-schema/spec"

/**
 * Create an Draft Auth client.
 *
 * @param input - Configure the client.
 */
export const createClient = (input: ClientInput): Client => {
	const jwksCache = new Map<string, ReturnType<typeof createLocalJWKSet>>()
	const issuerCache = new Map<string, OidcDiscovery>()
	const issuer = input.issuer || process.env.DRAFTAUTH_ISSUER
	if (!issuer) throw new Error("No issuer")
	const f = input.fetch ?? (fetch as FetchLike)

	const getIssuer = async (): Promise<OidcDiscovery> => {
		const cached = issuerCache.get(issuer!)
		if (cached) return cached

		// Try OIDC discovery first
		try {
			const oidcDiscovery = (await f(`${issuer}/.well-known/openid-configuration`).then(
				(r: FetchResponse) => r.json()
			)) as OidcDiscovery

			if (oidcDiscovery.authorization_endpoint) {
				issuerCache.set(issuer!, oidcDiscovery)
				return oidcDiscovery
			}
		} catch {
			// Fallback to OAuth discovery
		}

		// Fallback to OAuth 2.0 Authorization Server Metadata
		const wellKnown = (await f(`${issuer}/.well-known/oauth-authorization-server`).then(
			(r: FetchResponse) => r.json()
		)) as OidcDiscovery
		issuerCache.set(issuer!, wellKnown)
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

	const result: Client = {
		async revoke(token: string, opts?: RevokeOptions): Promise<RevokeSuccess | RevokeError> {
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
						return { err: new UnsupportedTokenTypeError() }
					}
				} catch {
					// Continue to generic error
				}
				return { err: new TokenRevocationError(`Revocation failed: ${errorText}`) }
			}

			return { err: false }
		},

		async authorize(redirectURI: string, response: "code" | "token", opts?: AuthorizeOptions) {
			const wk = await getIssuer()
			const result = new URL(wk.authorization_endpoint)
			const challenge: Challenge = {
				state: crypto.randomUUID()
			}

			result.searchParams.set("client_id", input.clientID)
			result.searchParams.set("redirect_uri", redirectURI)
			result.searchParams.set("response_type", response)
			result.searchParams.set("state", challenge.state)

			if (opts?.provider) result.searchParams.set("provider", opts.provider)
			if (opts?.scopes) result.searchParams.set("scope", opts.scopes.join(" "))
			if (opts?.nonce) result.searchParams.set("nonce", opts.nonce)
			if (opts?.prompt) result.searchParams.set("prompt", opts.prompt)
			if (opts?.maxAge) result.searchParams.set("max_age", opts.maxAge.toString())
			if (opts?.uiLocales) result.searchParams.set("ui_locales", opts.uiLocales)
			if (opts?.idTokenHint) result.searchParams.set("id_token_hint", opts.idTokenHint)
			if (opts?.loginHint) result.searchParams.set("login_hint", opts.loginHint)

			if (opts?.pkce && response === "code") {
				const pkce = await generatePKCE()
				result.searchParams.set("code_challenge_method", "S256")
				result.searchParams.set("code_challenge", pkce.challenge)
				challenge.verifier = pkce.verifier
			}

			return {
				challenge,
				url: result.toString()
			}
		},

		async exchange(
			code: string,
			redirectURI: string,
			verifier?: string
		): Promise<ExchangeSuccess | ExchangeError> {
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

			const responseText = await response.text()

			if (!response.ok) {
				return {
					err: new InvalidAuthorizationCodeError()
				}
			}

			let json: unknown
			try {
				json = JSON.parse(responseText)
			} catch (error) {
				return {
					err: new InvalidAuthorizationCodeError()
				}
			}

			const tokenResponse = json as TokenResponse
			return {
				err: false,
				tokens: {
					access: tokenResponse.access_token,
					refresh: tokenResponse.refresh_token,
					expiresIn: tokenResponse.expires_in,
					...(tokenResponse.id_token && { idToken: tokenResponse.id_token }),
					...(tokenResponse.scope && { scope: tokenResponse.scope })
				}
			}
		},

		async refresh(
			refresh: string,
			opts?: RefreshOptions
		): Promise<RefreshSuccess | RefreshError> {
			if (opts?.access) {
				const decoded = decodeJwt(opts.access)
				if (!decoded) {
					return {
						err: new InvalidAccessTokenError()
					}
				}
				// allow 30s window for expiration
				if ((decoded.exp || 0) > Date.now() / 1000 + 30) {
					return {
						err: false
					}
				}
			}

			const wk = await getIssuer()
			const response = await f(wk.token_endpoint, {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded"
				},
				body: new URLSearchParams({
					grant_type: "refresh_token",
					refresh_token: refresh
				}).toString()
			})

			const responseText = await response.text()

			if (!response.ok) {
				return {
					err: new InvalidRefreshTokenError()
				}
			}

			let json: unknown
			try {
				json = JSON.parse(responseText)
			} catch (error) {
				return {
					err: new InvalidRefreshTokenError()
				}
			}

			const tokenResponse = json as TokenResponse
			return {
				err: false,
				tokens: {
					access: tokenResponse.access_token,
					refresh: tokenResponse.refresh_token,
					expiresIn: tokenResponse.expires_in,
					...(tokenResponse.id_token && { idToken: tokenResponse.id_token }),
					...(tokenResponse.scope && { scope: tokenResponse.scope })
				}
			}
		},

		async verify<T extends SubjectSchema>(
			subjects: T,
			token: string,
			options?: VerifyOptions
		): Promise<VerifyResult<T> | VerifyError> {
			const jwks = await getJWKS()
			try {
				const jwtResult = await jwtVerify<{
					mode: "access"
					type: keyof T
					properties: StandardSchemaV1.InferInput<T[keyof T]>
					scopes?: string[]
				}>(token, jwks, {
					issuer
				})

				const subjectType = jwtResult.payload.type
				const subjectSchema = subjects[subjectType]

				if (!subjectSchema) {
					return {
						err: new InvalidSubjectError()
					}
				}

				const validated = await subjectSchema["~standard"].validate(
					jwtResult.payload.properties
				)

				if (!validated.issues && jwtResult.payload.mode === "access") {
					return {
						aud: jwtResult.payload.aud as string,
						subject: {
							type: jwtResult.payload.type,
							properties: validated.value
						} as VerifyResult<T>["subject"],
						...(jwtResult.payload.scopes ? { scopes: jwtResult.payload.scopes } : {})
					}
				}

				return {
					err: new InvalidSubjectError()
				}
			} catch (e) {
				if (e instanceof errors.JWTExpired && options?.refresh) {
					const refreshed = await result.refresh(options.refresh)
					if (refreshed.err) return refreshed

					if (!refreshed.tokens) {
						return {
							err: new InvalidAccessTokenError()
						}
					}

					const verified = await result.verify(subjects, refreshed.tokens.access, {
						refresh: refreshed.tokens.refresh,
						issuer: options?.issuer,
						audience: options?.audience,
						fetch: options?.fetch
					})

					if (verified.err) return verified

					return {
						...verified,
						tokens: refreshed.tokens
					}
				}
				return {
					err: new InvalidAccessTokenError()
				}
			}
		},

		async userinfo(
			accessToken: string,
			opts?: UserInfoOptions
		): Promise<UserInfoResult | UserInfoError> {
			const wk = await getIssuer()
			if (!wk.userinfo_endpoint) {
				return { err: new InvalidAccessTokenError() }
			}

			const fetchFn = opts?.fetch ?? f
			const response = await fetchFn(wk.userinfo_endpoint, {
				headers: {
					Authorization: `Bearer ${accessToken}`
				}
			})

			if (!response.ok) {
				return { err: new InvalidAccessTokenError() }
			}

			const userinfo = (await response.json()) as Record<string, unknown>
			return { err: undefined, userinfo }
		},

		async verifyIdToken(idToken: string): Promise<IdTokenVerifyResult | IdTokenVerifyError> {
			const jwks = await getJWKS()
			try {
				const result = await jwtVerify<IdTokenClaims>(idToken, jwks, { issuer })
				return { err: undefined, claims: result.payload }
			} catch {
				return { err: new InvalidAccessTokenError() }
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
	return result
}
