/**
 * A list of errors that can be thrown by Draft Auth.
 *
 * You can use these errors to check the type of error and handle it. For example.
 *
 * ```ts
 * import { InvalidAuthorizationCodeError } from "@draftauth/core/error"
 *
 * if (err instanceof InvalidAuthorizationCodeError) {
 *   // handle invalid code error
 * }
 * ```
 *
 * @packageDocumentation
 */

/**
 * The OAuth server returned an error.
 */

export type OauthErrorType =
	| "invalid_request"
	| "invalid_grant"
	| "unauthorized_client"
	| "access_denied"
	| "unsupported_grant_type"
	| "server_error"
	| "temporarily_unavailable"

export class OauthError extends Error {
	public error: OauthErrorType
	public description: string

	constructor(error: OauthErrorType, description: string) {
		super(`${error} - ${description}`)
		this.error = error
		this.description = description
	}
}

/**
 * The `provider` needs to be passed in.
 */
export class MissingProviderError extends OauthError {
	constructor() {
		super(
			"invalid_request",
			"Must specify `provider` query parameter if `select` callback on issuer is not specified"
		)
	}
}

/**
 * The given parameter is missing.
 */
export class MissingParameterError extends OauthError {
	public parameter: string

	constructor(parameter: string) {
		super("invalid_request", `Missing parameter: ${parameter}`)
		this.parameter = parameter
	}
}

/**
 * The given client is not authorized to use the redirect URI that was passed in.
 */
export class UnauthorizedClientError extends OauthError {
	public clientID: string

	constructor(clientID: string, redirectURI: string) {
		super(
			"unauthorized_client",
			`Client ${clientID} is not authorized to use this redirect_uri: ${redirectURI}`
		)
		this.clientID = clientID
	}
}

/**
 * The browser was in an unknown state.
 *
 * This can happen when certain cookies have expired. Or the browser was switched in the middle
 * of the authentication flow.
 */
export class UnknownStateError extends Error {
	constructor() {
		super(
			"The browser was in an unknown state. This could be because certain cookies expired or the browser was switched in the middle of an authentication flow."
		)
	}
}

/**
 * The given subject is invalid.
 */
export class InvalidSubjectError extends Error {
	constructor() {
		super("Invalid subject")
	}
}

/**
 * The given refresh token is invalid.
 */
export class InvalidRefreshTokenError extends Error {
	constructor() {
		super("Invalid refresh token")
	}
}

/**
 * The given access token is invalid.
 */
export class InvalidAccessTokenError extends Error {
	constructor() {
		super("Invalid access token")
	}
}

/**
 * The given authorization code is invalid.
 */
export class InvalidAuthorizationCodeError extends Error {
	constructor() {
		super("Invalid authorization code")
	}
}

/**
 * The token type provided is not supported for revocation.
 */
export class UnsupportedTokenTypeError extends Error {
	constructor() {
		super("Unsupported token type")
	}
}

/**
 * An error occurred during token revocation.
 */
export class TokenRevocationError extends Error {}
