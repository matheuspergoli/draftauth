import type { StandardSchemaV1 } from "@standard-schema/spec"
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
	 */
	scopes?: string[]
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
	 * const { access, refresh } = exchanged.tokens
	 * ```
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
	 *   const { access, refresh } = next.tokens
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
	 *   const { access, refresh } = verified.tokens
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
}

/**
 * Create an Draft Auth client.
 *
 * @param input - Configure the client.
 */
export const createClient = (input: ClientInput): Client => {
	const jwksCache = new Map<string, ReturnType<typeof createLocalJWKSet>>()
	const issuerCache = new Map<string, WellKnown>()
	const issuer = input.issuer || process.env.DRAFTAUTH_ISSUER
	if (!issuer) throw new Error("No issuer")
	const f = input.fetch ?? (fetch as FetchLike)

	const getIssuer = async () => {
		const cached = issuerCache.get(issuer!)
		if (cached) return cached
		const wellKnown = (await f(`${issuer}/.well-known/oauth-authorization-server`).then(
			(r: FetchResponse) => r.json()
		)) as WellKnown
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
			const response = await f(`${issuer}/revoke`, {
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
			const result = new URL(`${issuer}/authorize`)
			const challenge: Challenge = {
				state: crypto.randomUUID()
			}
			result.searchParams.set("client_id", input.clientID)
			result.searchParams.set("redirect_uri", redirectURI)
			result.searchParams.set("response_type", response)
			result.searchParams.set("state", challenge.state)
			if (opts?.provider) result.searchParams.set("provider", opts.provider)
			if (opts?.pkce && response === "code") {
				const pkce = await generatePKCE()
				result.searchParams.set("code_challenge_method", "S256")
				result.searchParams.set("code_challenge", pkce.challenge)
				challenge.verifier = pkce.verifier
			}
			if (opts?.scopes) result.searchParams.set("scope", opts.scopes.join(" "))
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
			const response = await f(`${issuer}/token`, {
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
					expiresIn: tokenResponse.expires_in
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

			const response = await f(`${issuer}/token`, {
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
					expiresIn: tokenResponse.expires_in
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
		}
	}
	return result
}
