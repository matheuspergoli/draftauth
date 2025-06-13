import type { Context, Hono } from "hono"
/**
 * Token endpoint handler for Draft Auth issuer.
 * Handles authorization_code, refresh_token, and client_credentials grant types
 * with full OAuth 2.0 and OIDC compliance.
 */
import { cors } from "hono/cors"
import { validatePKCE } from "../pkce"
import { parseScopes, validateScopes } from "../scopes"
import { Storage, type StorageAdapter } from "../storage/storage"

/**
 * Token generation response with OIDC ID token support.
 * Used internally for generating access, refresh, and ID tokens.
 */
interface TokenGenerationResult {
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
 * Authorization code storage payload with OIDC parameters.
 * Contains all necessary data to exchange an authorization code for tokens.
 */
interface CodeStoragePayload {
	/** Subject type identifier */
	type: string
	/** Subject properties/claims */
	properties: unknown
	/** Client identifier that requested the authorization */
	clientID: string
	/** Redirect URI used in the authorization request */
	redirectURI: string
	/** Resolved subject identifier for JWT */
	subject: string
	/** Requested OAuth 2.0 scopes */
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
	/** PKCE challenge data for code verification */
	pkce?: {
		challenge: string
		method: "S256"
	}
}

/**
 * Refresh token storage payload with OIDC parameters.
 * Contains data needed to issue new tokens from a refresh token.
 */
interface RefreshTokenStoragePayload {
	/** Subject type identifier */
	type: string
	/** Subject properties/claims */
	properties: unknown
	/** Resolved subject identifier for JWT */
	subject: string
	/** Client identifier that owns this refresh token */
	clientID: string
	/** OAuth 2.0 scopes associated with this token */
	scopes?: string[]
	/** Timestamp when the refresh token was first used */
	timeUsed?: number
}

/**
 * Token generation dependencies provided by the issuer.
 */
interface TokenDependencies<Result = unknown> {
	/** Storage adapter for persisting codes and tokens */
	storage: StorageAdapter
	/** Function to generate JWT tokens */
	generateTokens: (
		context: Context,
		payload: {
			type: string
			properties: unknown
			subject: string
			clientID: string
			scopes?: string[]
			nonce?: string
			sessionId?: string
			authTime?: number
			ttl: {
				access: number
				refresh: number
			}
		},
		options?: {
			generateRefreshToken?: boolean
		}
	) => Promise<TokenGenerationResult>
	/** TTL configuration for tokens */
	ttl: {
		access: number
		refresh: number
		refreshReuse: number
		refreshRetention: number
	}
	/** Auth utilities for token invalidation */
	auth: {
		invalidate: (subject: string) => Promise<void>
	}
	/** Refresh callback from issuer input */
	refresh?: (
		payload: {
			type: string
			properties: unknown
			subject: string
			clientID: string
			scopes?: string[]
		},
		req: Request
	) => Promise<
		| {
				type: string
				properties: unknown
				subject?: string
				scopes?: string[]
		  }
		| undefined
	>
	/** Success callback from issuer input */
	success: (
		responder: {
			subject: (
				type: string,
				properties: unknown,
				opts?: { ttl?: { access?: number; refresh?: number }; subject?: string }
			) => Promise<Response>
		},
		result: Result,
		req: Request,
		clientID: string
	) => Promise<Response>
	/** Providers configuration for client_credentials flow */
	providers: Record<
		string,
		{
			client?: (params: {
				clientID: string
				clientSecret: string
				params: Record<string, string>
			}) => Promise<unknown>
		}
	>
	/** Resolve subject function */
	resolveSubject: (type: string, properties: unknown) => Promise<string>
}

/**
 * Registers the OAuth 2.0 token endpoint handler with the Hono application.
 * Supports authorization_code, refresh_token, and client_credentials grant types.
 *
 * @param app - Hono application instance
 * @param dependencies - Token generation dependencies
 */
export const registerTokenEndpoint = <T, R>(
	app: Hono<{ Variables: { authorization: T } }>,
	dependencies: TokenDependencies<R>
): void => {
	const { storage, generateTokens, ttl, auth, refresh, success, providers, resolveSubject } =
		dependencies

	const {
		access: ttlAccess,
		refresh: ttlRefresh,
		refreshReuse: ttlRefreshReuse,
		refreshRetention: ttlRefreshRetention
	} = ttl

	app.post(
		"/token",
		cors({
			origin: "*",
			allowHeaders: ["*"],
			allowMethods: ["POST"],
			credentials: false
		}),
		async (c) => {
			const form = await c.req.formData()
			const grantType = form.get("grant_type")
			const scope = form.get("scope") as string | null

			// Authorization Code Grant
			if (grantType === "authorization_code") {
				const code = form.get("code")
				if (!code) {
					return c.json(
						{
							error: "invalid_request",
							error_description: "Missing code"
						},
						400
					)
				}

				const key = ["oauth:code", code.toString()]
				const payload = await Storage.get<CodeStoragePayload>(storage, key)
				if (!payload) {
					return c.json(
						{
							error: "invalid_grant",
							error_description: "Authorization code has been used or expired"
						},
						400
					)
				}

				// Validate redirect URI
				if (payload.redirectURI !== form.get("redirect_uri")) {
					return c.json(
						{
							error: "invalid_redirect_uri",
							error_description: "Redirect URI mismatch"
						},
						400
					)
				}

				// Validate client ID
				if (payload.clientID !== form.get("client_id")) {
					return c.json(
						{
							error: "unauthorized_client",
							error_description: "Client is not authorized to use this authorization code"
						},
						403
					)
				}

				// PKCE validation
				if (payload.pkce) {
					const codeVerifier = form.get("code_verifier")?.toString()
					if (!codeVerifier) {
						return c.json(
							{
								error: "invalid_grant",
								error_description: "Missing code_verifier"
							},
							400
						)
					}

					if (
						!(await validatePKCE(codeVerifier, payload.pkce.challenge, payload.pkce.method))
					) {
						return c.json(
							{
								error: "invalid_grant",
								error_description: "Code verifier does not match"
							},
							400
						)
					}
				}

				const finalScopes = validateScopes(scope, payload.scopes)
				const tokens = await generateTokens(c, {
					...payload,
					scopes: finalScopes
				})

				// Remove used authorization code
				await Storage.remove(storage, key)

				const response: Record<string, string | number> = {
					access_token: tokens.access,
					token_type: "Bearer",
					expires_in: tokens.expiresIn,
					refresh_token: tokens.refresh,
					...(finalScopes && { scope: finalScopes.join(" ") }),
					...(tokens.id_token && { id_token: tokens.id_token })
				}

				return c.json(response)
			}

			// Refresh Token Grant
			if (grantType === "refresh_token") {
				const refreshToken = form.get("refresh_token")
				if (!refreshToken) {
					return c.json(
						{
							error: "invalid_request",
							error_description: "Missing refresh_token"
						},
						400
					)
				}

				const splits = refreshToken.toString().split(":")
				const token = splits.pop()!
				const subject = splits.join(":")
				const key = ["oauth:refresh", subject, token]
				const payload = await Storage.get<RefreshTokenStoragePayload>(storage, key)

				if (!payload) {
					return c.json(
						{
							error: "invalid_grant",
							error_description: "Refresh token has been used or expired"
						},
						400
					)
				}

				// Execute refresh callback if provided
				if (refresh) {
					try {
						const refreshResult = await refresh(
							{
								type: payload.type,
								properties: payload.properties,
								subject: payload.subject,
								clientID: payload.clientID,
								scopes: payload.scopes
							},
							c.req.raw
						)

						if (!refreshResult) {
							await auth.invalidate(subject)
							return c.json(
								{
									error: "invalid_grant",
									error_description: "Refresh token has been revoked"
								},
								400
							)
						}

						// Update payload with refresh result
						payload.type = refreshResult.type
						payload.properties = refreshResult.properties
						if (refreshResult.subject) {
							payload.subject = refreshResult.subject
						}
						if (refreshResult.scopes) {
							payload.scopes = refreshResult.scopes
						}
					} catch (error) {
						console.error("Refresh callback error:", error)
						return c.json(
							{
								error: "server_error",
								error_description: "Internal server error during token refresh"
							},
							500
						)
					}
				}

				// Handle refresh token reuse logic
				const generateRefreshToken = !payload.timeUsed
				if (ttlRefreshReuse <= 0) {
					// No reuse interval, remove the refresh token immediately
					await Storage.remove(storage, key)
				} else if (!payload.timeUsed) {
					payload.timeUsed = Date.now()
					await Storage.set(storage, key, payload, ttlRefreshReuse + ttlRefreshRetention)
				} else if (Date.now() > payload.timeUsed + ttlRefreshReuse * 1000) {
					// Token was reused past the allowed interval
					await auth.invalidate(subject)
					return c.json(
						{
							error: "invalid_grant",
							error_description: "Refresh token has been used or expired"
						},
						400
					)
				}

				const finalScopes = validateScopes(scope, payload.scopes)
				const tokens = await generateTokens(
					c,
					{
						type: payload.type,
						properties: payload.properties,
						subject: payload.subject,
						clientID: payload.clientID,
						scopes: finalScopes,
						ttl: {
							access: ttlAccess,
							refresh: ttlRefresh
						}
					},
					{
						generateRefreshToken
					}
				)

				const response: Record<string, string | number> = {
					access_token: tokens.access,
					token_type: "Bearer",
					refresh_token: tokens.refresh,
					expires_in: tokens.expiresIn,
					...(finalScopes && { scope: finalScopes.join(" ") }),
					...(tokens.id_token && { id_token: tokens.id_token })
				}

				return c.json(response)
			}

			// Client Credentials Grant
			if (grantType === "client_credentials") {
				const provider = form.get("provider")
				if (!provider) {
					return c.json({ error: "missing `provider` form value" }, 400)
				}

				const match = providers[provider.toString()]
				if (!match) {
					return c.json({ error: "invalid `provider` query parameter" }, 400)
				}

				if (!match.client) {
					return c.json({ error: "this provider does not support client_credentials" }, 400)
				}

				const clientID = form.get("client_id")
				const clientSecret = form.get("client_secret")
				if (!clientID) {
					return c.json({ error: "missing `client_id` form value" }, 400)
				}
				if (!clientSecret) {
					return c.json({ error: "missing `client_secret` form value" }, 400)
				}

				// Extract all form parameters for provider
				const params: Record<string, string> = {}
				for (const [key, value] of form.entries()) {
					if (typeof value === "string") {
						params[key] = value
					}
				}

				const response = await match.client({
					clientID: clientID.toString(),
					clientSecret: clientSecret.toString(),
					params
				})

				return success(
					{
						async subject(type, properties, opts) {
							const tokens = await generateTokens(c, {
								type: type as string,
								subject: opts?.subject || (await resolveSubject(type, properties)),
								properties,
								clientID: clientID.toString(),
								scopes: parseScopes(scope),
								ttl: {
									access: opts?.ttl?.access ?? ttlAccess,
									refresh: opts?.ttl?.refresh ?? ttlRefresh
								}
							})

							const tokenResponse: Record<string, string> = {
								access_token: tokens.access,
								token_type: "Bearer",
								refresh_token: tokens.refresh,
								...(tokens.id_token && { id_token: tokens.id_token })
							}
							return c.json(tokenResponse)
						}
					},
					{
						provider: provider.toString(),
						...(response && typeof response === "object" ? response : {})
					},
					c.req.raw,
					clientID.toString()
				)
			}

			return c.json(
				{
					error: "unsupported_grant_type",
					error_description:
						"The authorization grant type is not supported by the authorization server"
				},
				400
			)
		}
	)
}
