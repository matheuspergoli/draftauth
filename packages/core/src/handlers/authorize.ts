/**
 * Authorization endpoint handler for Draft Auth issuer.
 * Handles OAuth 2.0 and OIDC authorization flows with SSO support.
 */
import type { Context, Hono } from "hono"
import { getCookie } from "hono/cookie"
import { MissingParameterError, OauthError, UnauthorizedClientError } from "../error"
import { parseScopes } from "../scopes"
import type { SsoSessionData } from "../sso"
import { Storage, type StorageAdapter } from "../storage/storage"
import type { AuthorizationState, CodeStoragePayload, TokenGenerationResult } from "../types"

/**
 * Authorization handler dependencies provided by the issuer.
 */
interface AuthorizeDependencies {
	/** Storage adapter for persisting authorization state and SSO sessions */
	storage: StorageAdapter
	/** Allow check function for client authorization */
	allow: () => (
		input: { clientID: string; redirectURI: string; audience?: string },
		req: Request
	) => Promise<boolean>
	/** Authentication utilities */
	auth: {
		set: (c: Context, key: string, ttl: number, value: unknown) => Promise<void>
		unset: (c: Context, key: string) => Promise<void>
		forward: (c: Context, response: Response) => Response
	}
	/** TTL for OAuth state storage */
	ttlOauthState: number
	/** TTL configuration for tokens */
	ttl: {
		access: number
		refresh: number
	}
	/** Provider selection UI function */
	select: () => (providers: Record<string, string>, req: Request) => Promise<Response>
	/** Available providers configuration */
	providers: Record<string, { type: string }>
	/** Optional start callback */
	start?: (req: Request) => Promise<void>
	/** SSO configuration */
	sso?: {
		enabled?: boolean
		isSsoUserStillValid?: (
			userId: string,
			sessionData: SsoSessionData,
			req: Request
		) => Promise<boolean>
		getSsoUserProperties?: (
			userId: string,
			sessionData: SsoSessionData,
			req: Request,
			clientID: string,
			scopes: string[]
		) => Promise<Record<string, unknown>>
	}
	/** Refresh callback for updating claims */
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
	/** Token generation function */
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
		}
	) => Promise<TokenGenerationResult>
	/** Subject resolver function */
	resolveSubject: (type: string, properties: unknown) => Promise<string>
	/** SSO utilities */
	ssoUtils: {
		getSsoCookieName: (c: Context) => string
		deleteSsoCookie: (c: Context) => void
		setSsoCookie: (c: Context, sessionId: string) => void
		acquireSsoLock: <T>(sessionId: string, callback: () => Promise<T>) => Promise<T>
	}
}

/**
 * Registers the OAuth 2.0/OIDC authorization endpoint handler with the Hono application.
 * Handles authorization code flow with SSO support and OIDC compliance.
 *
 * @param app - Hono application instance
 * @param dependencies - Authorization handler dependencies
 */
export const registerAuthorizeEndpoint = (
	app: Hono<{ Variables: { authorization: AuthorizationState } }>,
	dependencies: AuthorizeDependencies
): void => {
	const {
		storage,
		allow,
		auth,
		ttlOauthState,
		ttl,
		select,
		providers,
		start,
		sso,
		refresh,
		generateTokens,
		resolveSubject,
		ssoUtils
	} = dependencies

	const { access: ttlAccess, refresh: ttlRefresh } = ttl
	const ssoEnabled = sso?.enabled || false
	const { getSsoCookieName, deleteSsoCookie, setSsoCookie, acquireSsoLock } = ssoUtils

	app.get("/authorize", async (c) => {
		// Extract OAuth 2.0 and OIDC parameters
		const provider = c.req.query("provider")
		const response_type = c.req.query("response_type")
		const redirect_uri = c.req.query("redirect_uri")
		const state = c.req.query("state")
		const client_id = c.req.query("client_id")
		const audience = c.req.query("audience")
		const code_challenge = c.req.query("code_challenge")
		const code_challenge_method = c.req.query("code_challenge_method")
		const scope = c.req.query("scope")
		const nonce = c.req.query("nonce")
		const prompt = c.req.query("prompt")
		const max_age = c.req.query("max_age")
		const id_token_hint = c.req.query("id_token_hint")
		const login_hint = c.req.query("login_hint")

		// Build authorization state
		const authorization: AuthorizationState = {
			response_type,
			redirect_uri,
			state,
			client_id,
			audience,
			scope,
			nonce,
			prompt,
			max_age: max_age ? Number.parseInt(max_age) : undefined,
			id_token_hint,
			login_hint,
			scopes: parseScopes(scope).length > 0 ? parseScopes(scope) : ["openid"],
			pkce:
				code_challenge && code_challenge_method
					? {
							challenge: code_challenge,
							method: code_challenge_method as "S256"
						}
					: undefined
		}
		c.set("authorization", authorization)

		// OIDC implicit flow validation
		if (scope?.includes("openid") && response_type?.includes("id_token") && !nonce) {
			throw new OauthError(
				"invalid_request",
				"nonce is required for implicit flow with id_token"
			)
		}

		// SSO handling
		if (ssoEnabled) {
			const ssoCookieName = getSsoCookieName(c)
			const ssoSessionIdFromCookie = getCookie(c, ssoCookieName)

			if (ssoSessionIdFromCookie) {
				const ssoResult = await acquireSsoLock(ssoSessionIdFromCookie, async () => {
					const ssoSessionKey = ["sso:session", ssoSessionIdFromCookie]
					let ssoSessionData = await Storage.get<SsoSessionData>(storage, ssoSessionKey)

					// Validate session structure and expiration
					const now = Math.floor(Date.now() / 1000)
					let isSsoSessionValid = ssoSessionData?.userId && ssoSessionData.exp > now

					// Handle OIDC prompt parameter
					if (prompt === "none" && !isSsoSessionValid) {
						const errorUrl = new URL(redirect_uri!)
						errorUrl.searchParams.set("error", "login_required")
						if (state) errorUrl.searchParams.set("state", state)
						return c.redirect(errorUrl.toString(), 302)
					}

					if (prompt === "login" && ssoSessionData) {
						// Force re-authentication
						await Storage.remove(storage, ssoSessionKey)
						deleteSsoCookie(c)
						ssoSessionData = null
						isSsoSessionValid = false
					}

					// Check max_age requirement
					if (isSsoSessionValid && ssoSessionData && max_age) {
						const maxAgeSeconds = Number.parseInt(max_age)
						if (now - ssoSessionData.auth_time > maxAgeSeconds) {
							await Storage.remove(storage, ssoSessionKey)
							deleteSsoCookie(c)
							ssoSessionData = null
							isSsoSessionValid = false
						}
					}

					// Process valid SSO session
					if (isSsoSessionValid && ssoSessionData) {
						if (!client_id || !redirect_uri || !response_type) {
							throw new MissingParameterError("client_id, redirect_uri, or response_type")
						}

						// Client authorization check
						if (
							!(await allow()(
								{ clientID: client_id, redirectURI: redirect_uri, audience },
								c.req.raw
							))
						) {
							if (prompt === "none") {
								const errorUrl = new URL(redirect_uri)
								errorUrl.searchParams.set("error", "unauthorized_client")
								if (state) errorUrl.searchParams.set("state", state)
								return c.redirect(errorUrl.toString(), 302)
							}
							throw new UnauthorizedClientError(client_id, redirect_uri)
						}

						// Build authorization state for this app
						const authorizationForThisApp: AuthorizationState = {
							client_id,
							redirect_uri,
							response_type,
							state: state as string,
							nonce,
							prompt,
							max_age: authorization.max_age,
							id_token_hint,
							login_hint,
							scopes: parseScopes(scope),
							pkce:
								code_challenge && code_challenge_method
									? { challenge: code_challenge, method: code_challenge_method as "S256" }
									: undefined,
							audience
						}
						await auth.set(c, "authorization", ttlOauthState, authorizationForThisApp)
						c.set("authorization", authorizationForThisApp)

						let finalSubjectProperties = ssoSessionData.originalProperties
						let finalScopes = parseScopes(scope).length > 0 ? parseScopes(scope) : ["openid"]

						// Refresh user properties if callback provided
						if (refresh) {
							try {
								const refreshedClaims = await refresh(
									{
										type: ssoSessionData.subjectType,
										properties: ssoSessionData.originalProperties,
										subject: ssoSessionData.resolvedSubject,
										clientID: client_id,
										scopes: finalScopes
									},
									c.req.raw
								)
								if (refreshedClaims) {
									finalSubjectProperties = refreshedClaims.properties as Record<
										string,
										unknown
									>
									finalScopes = refreshedClaims.scopes ?? finalScopes
								} else {
									await Storage.remove(storage, ssoSessionKey)
									deleteSsoCookie(c)
									return c.redirect(c.req.url, 302)
								}
							} catch {
								finalSubjectProperties = ssoSessionData.originalProperties
							}
						}

						const resolvedSsoUserJwtSubject =
							ssoSessionData.resolvedSubject ||
							(await resolveSubject(ssoSessionData.subjectType, finalSubjectProperties))

						// Handle authorization code flow
						if (authorizationForThisApp.response_type === "code") {
							const code = crypto.randomUUID()
							const codePayload: CodeStoragePayload = {
								type: ssoSessionData.subjectType,
								properties: finalSubjectProperties,
								subject: resolvedSsoUserJwtSubject,
								redirectURI: authorizationForThisApp.redirect_uri!,
								clientID: authorizationForThisApp.client_id!,
								pkce: authorizationForThisApp.pkce,
								scopes: finalScopes,
								nonce: authorizationForThisApp.nonce,
								sessionId: ssoSessionData.sid,
								authTime: ssoSessionData.auth_time,
								ttl: { access: ttlAccess, refresh: ttlRefresh }
							}

							await Storage.set(storage, ["oauth:code", code], codePayload, 60)

							const location = new URL(authorizationForThisApp.redirect_uri!)
							location.searchParams.set("code", code)
							if (authorizationForThisApp.state) {
								location.searchParams.set("state", authorizationForThisApp.state)
							}
							await auth.unset(c, "authorization")
							setSsoCookie(c, ssoSessionIdFromCookie)
							return c.redirect(location.toString(), 302)
						}

						// Handle implicit and hybrid flows
						if (
							authorizationForThisApp.response_type === "token" ||
							authorizationForThisApp.response_type?.includes("id_token")
						) {
							const tokens = await generateTokens(c, {
								type: ssoSessionData.subjectType,
								properties: finalSubjectProperties,
								subject: resolvedSsoUserJwtSubject,
								clientID: client_id,
								scopes: finalScopes,
								nonce: authorizationForThisApp.nonce,
								sessionId: ssoSessionData.sid,
								authTime: ssoSessionData.auth_time,
								ttl: { access: ttlAccess, refresh: ttlRefresh }
							})

							const location = new URL(authorizationForThisApp.redirect_uri!)
							const hashParams = new URLSearchParams()

							if (authorizationForThisApp.response_type.includes("token")) {
								hashParams.set("access_token", tokens.access)
								hashParams.set("token_type", "Bearer")
								hashParams.set("expires_in", tokens.expiresIn.toString())
							}

							if (
								authorizationForThisApp.response_type.includes("id_token") &&
								tokens.id_token
							) {
								hashParams.set("id_token", tokens.id_token)
							}

							if (authorizationForThisApp.state) {
								hashParams.set("state", authorizationForThisApp.state)
							}

							location.hash = hashParams.toString()
							await auth.unset(c, "authorization")
							setSsoCookie(c, ssoSessionIdFromCookie)
							return c.redirect(location.toString(), 302)
						}

						throw new OauthError(
							"unsupported_response_type",
							`Response type ${authorizationForThisApp.response_type} not supported for SSO`
						)
					}

					return null
				})

				if (ssoResult !== null) {
					return ssoResult as Response
				}
			}
		}

		// Parameter validation
		if (!redirect_uri) {
			return c.text("Missing redirect_uri", { status: 400 })
		}

		if (!response_type) {
			throw new MissingParameterError("response_type")
		}

		if (!client_id) {
			throw new MissingParameterError("client_id")
		}

		// Execute start callback
		if (start) {
			await start(c.req.raw)
		}

		// Client authorization check
		if (
			!(await allow()(
				{
					clientID: client_id,
					redirectURI: redirect_uri,
					audience
				},
				c.req.raw
			))
		) {
			throw new UnauthorizedClientError(client_id, redirect_uri)
		}

		// Store authorization state
		await auth.set(c, "authorization", ttlOauthState, authorization)

		// Handle provider selection
		if (provider) {
			return c.redirect(`/${provider}/authorize`)
		}

		const availableProviders = Object.keys(providers)
		if (availableProviders.length === 1) {
			return c.redirect(`/${availableProviders[0]}/authorize`)
		}

		// Show provider selection UI
		return auth.forward(
			c,
			await select()(
				Object.fromEntries(Object.entries(providers).map(([key, value]) => [key, value.type])),
				c.req.raw
			)
		)
	})
}
