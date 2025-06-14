/**
 * Error classes and types for Draft Auth operations.
 * Provides comprehensive error handling for OAuth 2.0, OIDC, and authentication flows.
 *
 * ## Usage
 *
 * ```ts
 * import {
 *   InvalidAuthorizationCodeError,
 *   OauthError,
 *   UnknownStateError
 * } from "@draftauth/core/error"
 *
 * try {
 *   await client.exchange(code, redirectUri)
 * } catch (error) {
 *   if (error instanceof InvalidAuthorizationCodeError) {
 *     // Handle invalid authorization code
 *     // Authorization code expired or invalid
 *   } else if (error instanceof OauthError) {
 *     // Handle OAuth-specific errors
 *     // OAuth error: error.error - error.description
 *   }
 * }
 * ```
 *
 * ## Error Categories
 *
 * - **OAuth Errors**: Standard OAuth 2.0 error responses
 * - **Token Errors**: Issues with access tokens, refresh tokens, and authorization codes
 * - **Client Errors**: Problems with client configuration and authorization
 * - **State Errors**: Session and flow state management issues
 *
 * @packageDocumentation
 */

/**
 * Standard OAuth 2.0 error types
 * These error codes are returned by OAuth authorization servers.
 */
export type OauthErrorType =
	| "invalid_request" // Request is missing required parameter or malformed
	| "invalid_client" // Client authentication failed
	| "invalid_grant" // Authorization grant is invalid, expired, or revoked
	| "unauthorized_client" // Client is not authorized to use this grant type
	| "access_denied" // Resource owner denied the request
	| "unsupported_grant_type" // Grant type is not supported by the server
	| "server_error" // Server encountered an unexpected condition
	| "temporarily_unavailable" // Service is temporarily overloaded or down
	| "unsupported_response_type" // Response type is not supported

/**
 * Base OAuth 2.0 error class for handling standard OAuth error responses.
 * Contains both the error code and human-readable description.
 */
export class OauthError extends Error {
	/** The OAuth error code as defined in the specification */
	public readonly error: OauthErrorType
	/** Human-readable description of the error */
	public readonly description: string

	/**
	 * Creates a new OAuth error with the specified error code and description.
	 *
	 * @param error - The OAuth error type
	 * @param description - Human-readable error description
	 *
	 * @example
	 * ```ts
	 * throw new OauthError("invalid_grant", "Authorization code has expired")
	 * ```
	 */
	constructor(error: OauthErrorType, description: string) {
		super(`${error} - ${description}`)
		this.name = "OauthError"
		this.error = error
		this.description = description
	}
}

/**
 * Error thrown when a provider parameter is missing from the authorization request.
 * Occurs when multiple providers are configured but no specific provider is selected.
 */
export class MissingProviderError extends OauthError {
	/**
	 * Creates a missing provider error.
	 * Thrown when the provider query parameter is required but not provided.
	 */
	constructor() {
		super(
			"invalid_request",
			"Must specify `provider` query parameter if `select` callback on issuer is not specified"
		)
		this.name = "MissingProviderError"
	}
}

/**
 * Error thrown when a required parameter is missing from a request.
 * Used for validating OAuth request parameters.
 */
export class MissingParameterError extends OauthError {
	/** The name of the missing parameter */
	public readonly parameter: string

	/**
	 * Creates a missing parameter error.
	 *
	 * @param parameter - The name of the missing parameter
	 *
	 * @example
	 * ```ts
	 * throw new MissingParameterError("client_id")
	 * ```
	 */
	constructor(parameter: string) {
		super("invalid_request", `Missing parameter: ${parameter}`)
		this.name = "MissingParameterError"
		this.parameter = parameter
	}
}

/**
 * Error thrown when a client is not authorized to use a specific redirect URI.
 * Prevents unauthorized clients from hijacking authorization codes.
 */
export class UnauthorizedClientError extends OauthError {
	/** The client ID that attempted unauthorized access */
	public readonly clientID: string

	/**
	 * Creates an unauthorized client error.
	 *
	 * @param clientID - The client ID attempting unauthorized access
	 * @param redirectURI - The unauthorized redirect URI
	 *
	 * @example
	 * ```ts
	 * throw new UnauthorizedClientError("malicious-client", "https://evil.com/callback")
	 * ```
	 */
	constructor(clientID: string, redirectURI: string) {
		super(
			"unauthorized_client",
			`Client ${clientID} is not authorized to use this redirect_uri: ${redirectURI}`
		)
		this.name = "UnauthorizedClientError"
		this.clientID = clientID
	}
}

/**
 * Error thrown when the authentication flow is in an unknown or invalid state.
 *
 * ## Common Causes
 * - Session cookies have expired during the authentication flow
 * - User switched browsers or devices mid-flow
 * - Authentication state was manually tampered with
 * - Server session storage was cleared
 *
 * @example
 * ```ts
 * // In provider callback handling
 * const state = await getAuthState(request)
 * if (!state) {
 *   throw new UnknownStateError()
 * }
 * ```
 */
export class UnknownStateError extends Error {
	/**
	 * Creates an unknown state error.
	 * Indicates that the authentication flow cannot continue due to missing state.
	 */
	constructor() {
		super(
			"The browser was in an unknown state. This could be because certain cookies expired or the browser was switched in the middle of an authentication flow."
		)
		this.name = "UnknownStateError"
	}
}

/**
 * Error thrown when a subject (user identifier) is invalid or malformed.
 * Used during token verification and subject validation.
 *
 * @example
 * ```ts
 * // During token verification
 * const subject = extractSubject(token)
 * if (!isValidSubject(subject)) {
 *   throw new InvalidSubjectError()
 * }
 * ```
 */
export class InvalidSubjectError extends Error {
	/**
	 * Creates an invalid subject error.
	 */
	constructor() {
		super("Invalid subject")
		this.name = "InvalidSubjectError"
	}
}

/**
 * Error thrown when a refresh token is invalid, expired, or revoked.
 * Occurs during token refresh operations.
 *
 * @example
 * ```ts
 * // During token refresh
 * try {
 *   const newTokens = await client.refresh(refreshToken)
 * } catch (error) {
 *   if (error instanceof InvalidRefreshTokenError) {
 *     // Redirect user to login again
 *     redirectToLogin()
 *   }
 * }
 * ```
 */
export class InvalidRefreshTokenError extends Error {
	/**
	 * Creates an invalid refresh token error.
	 */
	constructor() {
		super("Invalid refresh token")
		this.name = "InvalidRefreshTokenError"
	}
}

/**
 * Error thrown when an access token is invalid, expired, or malformed.
 * Occurs during token verification and API requests.
 *
 * @example
 * ```ts
 * // During API request
 * try {
 *   const user = await api.getUser(accessToken)
 * } catch (error) {
 *   if (error instanceof InvalidAccessTokenError) {
 *     // Try to refresh the token
 *     await refreshAccessToken()
 *   }
 * }
 * ```
 */
export class InvalidAccessTokenError extends Error {
	/**
	 * Creates an invalid access token error.
	 */
	constructor() {
		super("Invalid access token")
		this.name = "InvalidAccessTokenError"
	}
}

/**
 * Error thrown when an authorization code is invalid, expired, or already used.
 * Occurs during the token exchange step of the OAuth flow.
 *
 * @example
 * ```ts
 * // During authorization code exchange
 * try {
 *   const tokens = await client.exchange(code, redirectUri)
 * } catch (error) {
 *   if (error instanceof InvalidAuthorizationCodeError) {
 *     // Code may have expired or been used already
 *     redirectToAuthorize()
 *   }
 * }
 * ```
 */
export class InvalidAuthorizationCodeError extends Error {
	/**
	 * Creates an invalid authorization code error.
	 */
	constructor() {
		super("Invalid authorization code")
		this.name = "InvalidAuthorizationCodeError"
	}
}

/**
 * Error thrown when attempting to revoke a token type that is not supported.
 * Some authorization servers may only support revoking specific token types.
 *
 * @example
 * ```ts
 * // During token revocation
 * try {
 *   await client.revoke(idToken) // ID tokens may not be revocable
 * } catch (error) {
 *   if (error instanceof UnsupportedTokenTypeError) {
 *     // This token type cannot be revoked
 *   }
 * }
 * ```
 */
export class UnsupportedTokenTypeError extends Error {
	/**
	 * Creates an unsupported token type error.
	 */
	constructor() {
		super("Unsupported token type")
		this.name = "UnsupportedTokenTypeError"
	}
}

/**
 * Error thrown when token revocation fails for reasons other than unsupported token type.
 *
 * ## Common Causes
 * - Network connectivity issues
 * - Authorization server is down
 * - Token has already been revoked
 * - Invalid client credentials
 *
 * @example
 * ```ts
 * // During token revocation
 * try {
 *   await client.revoke(refreshToken)
 * } catch (error) {
 *   if (error instanceof TokenRevocationError) {
 *     // Revocation failed: error.message
 *   }
 * }
 * ```
 */
export class TokenRevocationError extends Error {
	/**
	 * Creates a token revocation error.
	 *
	 * @param message - Optional error message describing the revocation failure
	 */
	constructor(message?: string) {
		super(message || "Token revocation failed")
		this.name = "TokenRevocationError"
	}
}
