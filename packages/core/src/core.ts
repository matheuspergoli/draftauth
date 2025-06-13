/**
 * Core issuer implementation integrating all handlers.
 * Main entry point that assembles the complete Draft Auth server.
 */
import { type Context, Hono } from "hono"
import { deleteCookie, getCookie, setCookie } from "hono/cookie"
import type { StatusCode } from "hono/utils/http-status"
import { CompactEncrypt, SignJWT, compactDecrypt } from "jose"
import { type AllowCheckInput, defaultAllowCheck } from "./allow"
import { OauthError, UnknownStateError } from "./error"
import { encryptionKeys, signingKeys } from "./keys"
import type { Provider, ProviderRoute } from "./provider/provider"
import { parseScopes } from "./scopes"
import { Storage, type StorageAdapter } from "./storage/storage"
import type { SubjectPayload, SubjectSchema } from "./subject"
import { type Theme, setTheme } from "./themes/theme"
import { Select } from "./ui/select"
import { getRelativeUrl, lazy } from "./util"

// Import all handlers
import { registerAuthorizeEndpoint } from "./handlers/authorize"
import { registerDiscoveryEndpoints } from "./handlers/discovery"
import { registerRevokeEndpoint } from "./handlers/revoke"
import { registerTokenEndpoint } from "./handlers/token"
import { registerUserEndpoints } from "./handlers/user"

/**
 * SSO session data following OIDC Session Management specification.
 */
interface SsoSessionData<T = string> {
	/** Unique identifier of the user (OIDC 'sub' claim) */
	userId: string
	/** Type of the subject */
	subjectType: T
	/** User's email for OIDC email scope */
	email?: string
	/** User's full name for OIDC profile scope */
	name?: string
	/** User's preferred username for OIDC profile scope */
	preferred_username?: string
	/** User's profile picture URL for OIDC profile scope */
	picture?: string
	/** Authentication time (OIDC 'auth_time') */
	auth_time: number
	/** Session expiration time (OIDC 'exp') */
	exp: number
	/** Session ID for OIDC Session Management (OIDC 'sid') */
	sid: string
	/** Resolved subject identifier for JWT tokens */
	resolvedSubject: string
	/** Original subject properties from authentication */
	originalProperties: Record<string, unknown>
}

/**
 * Enhanced authorization state with OIDC parameters.
 */
interface AuthorizationState {
	redirect_uri?: string
	response_type?: string
	state?: string
	client_id?: string
	audience?: string
	scope?: string
	nonce?: string
	prompt?: string
	max_age?: number
	id_token_hint?: string
	login_hint?: string
	scopes?: string[]
	pkce?: {
		challenge: string
		method: "S256"
	}
}

/**
 * Token generation result with OIDC support.
 */
interface TokenGenerationResult {
	access: string
	expiresIn: number
	refresh: string
	id_token?: string
}

/**
 * SSO lock management for concurrent session operations.
 */
const ssoLocks: Record<string, Promise<unknown>> = {}

/**
 * Default constants for SSO and OAuth state management.
 */
const DEFAULT_SSO_COOKIE_NAME_SECURE = "__Host-draftauth-sso"
const DEFAULT_SSO_COOKIE_NAME_INSECURE = "draftauth-sso"
const DEFAULT_SSO_SESSION_TTL_SECONDS = 60 * 60 * 24 * 7
const DEFAULT_OAUTH_STATE_TTL_SECONDS = 60 * 10

/**
 * Sets the subject payload in the JWT token and returns the response.
 */
export interface OnSuccessResponder<T extends { type: string; properties: unknown }> {
	subject<Type extends T["type"]>(
		type: Type,
		properties: Extract<T, { type: Type }>["properties"],
		opts?: {
			ttl?: {
				access?: number
				refresh?: number
			}
			subject?: string
		}
	): Promise<Response>
}

/**
 * Main issuer input configuration interface.
 */
export interface IssuerInput<
	Providers extends Record<string, Provider<unknown>>,
	Subjects extends SubjectSchema,
	Result
> {
	/** The storage adapter for persisting tokens and sessions */
	storage: StorageAdapter
	/** Auth providers configuration */
	providers: Providers
	/** Subject schemas for token validation */
	subjects: Subjects
	/** Success callback for completed authentication */
	success(
		response: OnSuccessResponder<SubjectPayload<Subjects>>,
		input: Result,
		req: Request,
		clientID: string
	): Promise<Response>
	/** Theme configuration for UI */
	theme?: Theme
	/** TTL configuration for tokens and sessions */
	ttl?: {
		access?: number
		refresh?: number
		reuse?: number
		retention?: number
		oauthState?: number
		ssoSessionSeconds?: number
	}
	/** SSO configuration */
	sso?: {
		enabled?: boolean
		cookieName?: string
		postLogoutRedirectUri?: string
		postLogoutRedirectUris?: string[]
		cookieDomain?: string
		forceSecure?: boolean
		claimsSupported?: string[]
		isSsoUserStillValid?: (
			userId: string,
			ssoSessionData: SsoSessionData<SubjectPayload<Subjects>["type"]>,
			req: Request
		) => Promise<boolean>
		getSsoUserProperties?: (
			userId: string,
			ssoSessionData: SsoSessionData<SubjectPayload<Subjects>["type"]>,
			req: Request,
			clientID: string,
			scopes: string[]
		) => Promise<Record<string, unknown>>
		getSsoIdentifiers?: (
			properties: SubjectPayload<Subjects>["properties"],
			subjectType: SubjectPayload<Subjects>["type"]
		) => {
			userId: string
			email?: string
			name?: string
			preferred_username?: string
			picture?: string
		}
	}
	/** Supported OAuth 2.0 scopes */
	scopes_supported?: string[]
	/** Claims configuration for OIDC */
	claims?: {
		sub: string
		email?: string
		name?: string
		preferred_username?: string
		picture?: string
	}
	/** Provider selection UI function */
	select?(providers: Record<string, string>, req: Request): Promise<Response>
	/** Optional start callback */
	start?(req: Request): Promise<void>
	/** Error handling callback */
	error?(error: UnknownStateError, req: Request): Promise<Response>
	/** Client authorization check function */
	allow?(input: AllowCheckInput, req: Request): Promise<boolean>
	/** Refresh callback for updating user claims */
	refresh?(
		payload: {
			type: string
			properties: unknown
			subject: string
			clientID: string
			scopes?: string[]
		},
		req: Request
	): Promise<
		| {
				type: string
				properties: unknown
				subject?: string
				scopes?: string[]
		  }
		| undefined
	>
}

/**
 * Utility to check if request is HTTPS.
 */
const isHttpsRequest = (ctx: Context): boolean => {
	return (
		ctx.req.header("x-forwarded-proto") === "https" ||
		ctx.req.header("x-forwarded-ssl") === "on" ||
		ctx.req.url.startsWith("https://")
	)
}

/**
 * Create an Draft Auth server, a Hono app that handles OAuth 2.0 and OIDC flows.
 */
export const issuer = <
	Providers extends Record<string, Provider<unknown>>,
	Subjects extends SubjectSchema,
	Result = {
		[key in keyof Providers]: {
			provider: key
		} & (Providers[key] extends Provider<infer T> ? T : Record<string, unknown>)
	}[keyof Providers]
>(
	input: IssuerInput<Providers, Subjects, Result>
): Hono<{ Variables: { authorization: AuthorizationState } }> => {
	// Configuration setup
	const error =
		input.error ??
		((err: UnknownStateError) => {
			return new Response(err.message, {
				status: 400,
				headers: { "Content-Type": "text/plain" }
			})
		})

	const ttlAccess = input.ttl?.access ?? 60 * 60 * 24 * 30
	const ttlRefresh = input.ttl?.refresh ?? 60 * 60 * 24 * 365
	const ttlRefreshReuse = input.ttl?.reuse ?? 60
	const ttlRefreshRetention = input.ttl?.retention ?? 0
	const ttlOauthState = input.ttl?.oauthState ?? DEFAULT_OAUTH_STATE_TTL_SECONDS

	if (input.theme) {
		setTheme(input.theme)
	}

	// Lazy-loaded dependencies
	const select = lazy(() => input.select ?? Select())
	const allow = lazy(() => input.allow ?? defaultAllowCheck)
	const storage = input.storage
	const allSigning = lazy(() => signingKeys(storage))
	const allEncryption = lazy(() => encryptionKeys(storage))
	const signingKey = lazy(() => allSigning().then((all) => all[0]))
	const encryptionKey = lazy(() => allEncryption().then((all) => all[0]))

	// SSO configuration
	const ssoEnabled = input.sso?.enabled === true
	const ssoSessionTtlToUse = input.ttl?.ssoSessionSeconds ?? DEFAULT_SSO_SESSION_TTL_SECONDS
	const postLogoutRedirectUris = input.sso?.postLogoutRedirectUris ?? []
	const claimsSupported = input.sso?.claimsSupported ?? [
		"sub",
		"iss",
		"aud",
		"exp",
		"iat",
		"auth_time",
		"nonce",
		"name",
		"email",
		"preferred_username",
		"picture"
	]

	// Enhanced scopes for OIDC
	const standardOidcScopes = ["openid", "profile", "email", "address", "phone"]
	const allSupportedScopes = [
		...new Set([...standardOidcScopes, ...(input.scopes_supported ?? [])])
	]

	/**
	 * Resolves issuer URL from context.
	 */
	const issuer = (ctx: Context): string => {
		return new URL(getRelativeUrl(ctx, "/")).origin
	}

	/**
	 * Encrypts value for secure cookie storage.
	 */
	const encrypt = async (value: unknown): Promise<string> => {
		const key = await encryptionKey()
		if (!key) {
			throw new Error("Encryption key not available")
		}
		return await new CompactEncrypt(new TextEncoder().encode(JSON.stringify(value)))
			.setProtectedHeader({ alg: "RSA-OAEP-512", enc: "A256GCM" })
			.encrypt(key.public)
	}

	/**
	 * Decrypts value from secure cookie storage.
	 */
	const decrypt = async (value: string): Promise<unknown> => {
		const key = await encryptionKey()
		if (!key) {
			throw new Error("Encryption key not available")
		}
		return JSON.parse(
			new TextDecoder().decode(
				await compactDecrypt(value, key.private).then((result) => result.plaintext)
			)
		)
	}

	/**
	 * Resolves unique subject identifier from type and properties.
	 */
	const resolveSubject = async (type: string, properties: unknown): Promise<string> => {
		const jsonString = JSON.stringify(properties)
		const encoder = new TextEncoder()
		const data = encoder.encode(jsonString)
		const hashBuffer = await crypto.subtle.digest("SHA-256", data)
		const hashArray = Array.from(new Uint8Array(hashBuffer))
		const hashHex = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("")
		return `${type}:${hashHex.slice(0, 16)}`
	}

	/**
	 * Generates OIDC-compliant ID token when openid scope is present.
	 */
	const generateIdToken = async (
		ctx: Context,
		payload: {
			sub: string
			aud: string
			nonce?: string
			authTime: number
			sessionId?: string
			scopes: string[]
			properties: Record<string, unknown>
		}
	): Promise<string> => {
		const signingKeyData = await signingKey()
		if (!signingKeyData) {
			throw new Error("Signing key not available")
		}

		const now = Math.floor(Date.now() / 1000)
		const claims: Record<string, unknown> = {
			iss: issuer(ctx),
			sub: payload.sub,
			aud: payload.aud,
			exp: now + 3600, // ID tokens expire in 1 hour
			iat: now,
			auth_time: payload.authTime,
			...(payload.sessionId && { sid: payload.sessionId }),
			...(payload.nonce && { nonce: payload.nonce })
		}

		// Add profile claims based on scopes
		if (payload.scopes.includes("profile")) {
			if (payload.properties.name) claims.name = payload.properties.name
			if (payload.properties.preferred_username) {
				claims.preferred_username = payload.properties.preferred_username
			}
			if (payload.properties.picture) claims.picture = payload.properties.picture
		}

		if (payload.scopes.includes("email")) {
			if (payload.properties.email) claims.email = payload.properties.email
			if (payload.properties.email_verified !== undefined) {
				claims.email_verified = payload.properties.email_verified
			}
		}

		return await new SignJWT(claims)
			.setProtectedHeader({
				alg: signingKeyData.alg,
				kid: signingKeyData.id,
				typ: "JWT"
			})
			.sign(signingKeyData.private)
	}

	/**
	 * Generates access, refresh, and optionally ID tokens.
	 */
	const generateTokens = async (
		ctx: Context,
		value: {
			type: string
			properties: unknown
			subject: string
			clientID: string
			ttl: { access: number; refresh: number }
			timeUsed?: number
			nextToken?: string
			scopes?: string[]
			nonce?: string
			sessionId?: string
			authTime?: number
		},
		opts?: { generateRefreshToken?: boolean }
	): Promise<TokenGenerationResult> => {
		const refreshToken = value.nextToken ?? crypto.randomUUID()

		if (opts?.generateRefreshToken ?? true) {
			const nextRefreshToken = crypto.randomUUID()
			const refreshPayload = {
				type: value.type,
				properties: value.properties,
				clientID: value.clientID,
				subject: value.subject,
				scopes: value.scopes,
				nonce: value.nonce,
				sessionId: value.sessionId,
				authTime: value.authTime,
				ttl: value.ttl,
				nextToken: nextRefreshToken,
				timeUsed: value.timeUsed
			}

			const refreshKey = ["oauth:refresh", value.subject, refreshToken]
			await Storage.set(storage, refreshKey, refreshPayload, value.ttl.refresh)
		}

		const signingKeyData = await signingKey()
		if (!signingKeyData) {
			throw new Error("Signing key not available")
		}

		const now = Math.floor(Date.now() / 1000)
		const accessPayload = {
			mode: "access",
			type: value.type,
			properties: value.properties,
			sub: value.subject,
			aud: value.clientID,
			exp: now + value.ttl.access,
			iat: now,
			scopes: value.scopes
		}

		const access = await new SignJWT(accessPayload)
			.setProtectedHeader({
				alg: signingKeyData.alg,
				kid: signingKeyData.id,
				typ: "JWT"
			})
			.sign(signingKeyData.private)

		const tokens: TokenGenerationResult = {
			access,
			expiresIn: value.ttl.access,
			refresh: `${value.subject}:${refreshToken}`
		}

		// Generate ID token for OIDC flows
		if (value.scopes?.includes("openid")) {
			tokens.id_token = await generateIdToken(ctx, {
				sub: value.subject,
				aud: value.clientID,
				nonce: value.nonce,
				authTime: value.authTime ?? Math.floor(Date.now() / 1000),
				sessionId: value.sessionId,
				scopes: value.scopes,
				properties: value.properties as Record<string, unknown>
			})
		}

		return tokens
	}

	/**
	 * Gets SSO cookie name based on HTTPS and configuration.
	 */
	const getSsoCookieName = (ctx: Context): string => {
		const customName = input.sso?.cookieName
		if (customName) {
			if (customName.startsWith("__Host-") && input.sso?.cookieDomain) {
				console.warn("__Host- cookies cannot have domain attributes. Using fallback name.")
				const isHttps = isHttpsRequest(ctx)
				return isHttps ? "draftauth-sso-secure" : "draftauth-sso"
			}
			return customName
		}

		const isHttps = isHttpsRequest(ctx)
		if (input.sso?.cookieDomain) {
			return isHttps ? "draftauth-sso-secure" : "draftauth-sso"
		}

		return isHttps ? DEFAULT_SSO_COOKIE_NAME_SECURE : DEFAULT_SSO_COOKIE_NAME_INSECURE
	}

	/**
	 * Sets SSO cookie with appropriate security settings.
	 */
	const setSsoCookie = (ctx: Context, sessionId: string): void => {
		const isHttps = isHttpsRequest(ctx)
		const cookieName = getSsoCookieName(ctx)

		const cookieOptions = {
			path: "/",
			httpOnly: true,
			secure: isHttps || input.sso?.forceSecure,
			sameSite: "Lax" as const,
			maxAge: ssoSessionTtlToUse,
			...(input.sso?.cookieDomain && { domain: input.sso.cookieDomain })
		}

		setCookie(ctx, cookieName, sessionId, cookieOptions)
	}

	/**
	 * Deletes SSO cookie.
	 */
	const deleteSsoCookie = (ctx: Context): void => {
		const cookieName = getSsoCookieName(ctx)
		const isHttps = isHttpsRequest(ctx)

		const cookieOptions = {
			path: "/",
			httpOnly: true,
			secure: isHttps || input.sso?.forceSecure,
			sameSite: "Lax" as const,
			...(input.sso?.cookieDomain && { domain: input.sso.cookieDomain })
		}

		deleteCookie(ctx, cookieName, cookieOptions)
	}

	/**
	 * Acquires lock for SSO session operations to prevent race conditions.
	 */
	const acquireSsoLock = async <T>(
		sessionId: string,
		operation: () => Promise<T>
	): Promise<T> => {
		if (ssoLocks[sessionId]) {
			await ssoLocks[sessionId]
		}

		const promise = operation()
		ssoLocks[sessionId] = promise

		try {
			return await promise
		} finally {
			delete ssoLocks[sessionId]
		}
	}

	/**
	 * Gets authorization state from context.
	 */
	const getAuthorization = async (ctx: Context): Promise<AuthorizationState> => {
		const match = (await auth.get(ctx, "authorization")) || ctx.get("authorization")
		if (!match) throw new UnknownStateError()
		return match as AuthorizationState
	}

	/**
	 * Authentication utilities for providers.
	 */
	const auth = {
		async success(
			ctx: Context,
			properties: unknown,
			successOpts?: { invalidate?: (subject: string) => Promise<void> }
		) {
			const authorization = await getAuthorization(ctx)
			return await input.success(
				{
					async subject(type, properties, subjectOpts) {
						const subject = subjectOpts?.subject ?? (await resolveSubject(type, properties))
						await successOpts?.invalidate?.(subject)

						// Handle SSO session creation
						if (ssoEnabled) {
							let userIdForSso: string | undefined
							let userEmailForSso: string | undefined
							let userNameForSso: string | undefined
							let userPreferredUsernameForSso: string | undefined
							let userPictureForSso: string | undefined

							if (input.sso?.getSsoIdentifiers) {
								try {
									const identifiers = input.sso.getSsoIdentifiers(properties, type)
									userIdForSso = identifiers.userId
									userEmailForSso = identifiers.email
									userNameForSso = identifiers.name
									userPreferredUsernameForSso = identifiers.preferred_username
									userPictureForSso = identifiers.picture
								} catch (error) {
									console.error("Error extracting SSO identifiers:", error)
									const props = properties as Record<string, unknown>
									userIdForSso = props.id as string
									userEmailForSso = props.email as string
									userNameForSso = props.name as string
									userPreferredUsernameForSso = props.preferred_username as string
									userPictureForSso = props.picture as string
								}
							} else {
								const props = properties as Record<string, unknown>
								userIdForSso = props.id as string
								userEmailForSso = props.email as string
								userNameForSso = props.name as string
								userPreferredUsernameForSso = props.preferred_username as string
								userPictureForSso = props.picture as string
							}

							if (userIdForSso) {
								const ssoSessionId = crypto.randomUUID()
								const authTime = Math.floor(Date.now() / 1000)
								const ssoExpiresAt = authTime + ssoSessionTtlToUse

								const ssoSessionPayload: SsoSessionData<SubjectPayload<Subjects>["type"]> = {
									userId: userIdForSso,
									email: userEmailForSso,
									name: userNameForSso,
									preferred_username: userPreferredUsernameForSso,
									picture: userPictureForSso,
									subjectType: type,
									auth_time: authTime,
									exp: ssoExpiresAt,
									sid: ssoSessionId,
									resolvedSubject: subject,
									originalProperties: properties as Record<string, unknown>
								}

								await Storage.set(
									storage,
									["sso:session", ssoSessionId],
									ssoSessionPayload,
									ssoSessionTtlToUse
								)
								setSsoCookie(ctx, ssoSessionId)
							}
						}

						// Handle different response types
						if (authorization.response_type === "token") {
							const location = new URL(authorization.redirect_uri!)
							const scopes = parseScopes(authorization.scopes)
							const tokens = await generateTokens(ctx, {
								subject,
								type: type as string,
								properties,
								clientID: authorization.client_id!,
								scopes,
								nonce: authorization.nonce,
								sessionId: crypto.randomUUID(),
								authTime: Math.floor(Date.now() / 1000),
								ttl: {
									access: subjectOpts?.ttl?.access ?? ttlAccess,
									refresh: subjectOpts?.ttl?.refresh ?? ttlRefresh
								}
							})

							location.hash = new URLSearchParams({
								access_token: tokens.access,
								token_type: "Bearer",
								expires_in: tokens.expiresIn.toString(),
								...(tokens.id_token && { id_token: tokens.id_token }),
								...(authorization.state && { state: authorization.state })
							}).toString()

							return ctx.redirect(location.toString(), 302)
						}

						// Default: authorization code flow
						const code = crypto.randomUUID()
						const codePayload = {
							type: type as string,
							properties,
							subject,
							redirectURI: authorization.redirect_uri!,
							clientID: authorization.client_id!,
							pkce: authorization.pkce,
							scopes: parseScopes(authorization.scopes),
							nonce: authorization.nonce,
							sessionId: crypto.randomUUID(),
							authTime: Math.floor(Date.now() / 1000),
							ttl: {
								access: subjectOpts?.ttl?.access ?? ttlAccess,
								refresh: subjectOpts?.ttl?.refresh ?? ttlRefresh
							}
						}

						await Storage.set(storage, ["oauth:code", code], codePayload, 60)

						const location = new URL(authorization.redirect_uri!)
						location.searchParams.set("code", code)
						if (authorization.state) {
							location.searchParams.set("state", authorization.state)
						}

						return ctx.redirect(location.toString(), 302)
					}
				},
				{
					provider: "unknown", // This will be overridden by actual provider
					...(properties && typeof properties === "object" ? properties : {})
				} as Result,
				ctx.req.raw,
				authorization.client_id!
			)
		},

		forward(ctx: Context, response: Response) {
			return ctx.newResponse(
				response.body,
				response.status as StatusCode,
				Object.fromEntries(Array.from(response.headers.entries()))
			)
		},

		async set(ctx: Context, key: string, maxAge: number, value: unknown) {
			const isHttps = isHttpsRequest(ctx)
			setCookie(ctx, key, await encrypt(value), {
				maxAge,
				httpOnly: true,
				secure: isHttps,
				sameSite: isHttps ? "None" : "Lax"
			})
		},

		async get<T>(ctx: Context, key: string): Promise<T> {
			const raw = getCookie(ctx, key)
			if (!raw) return undefined as T
			try {
				const decrypted = await decrypt(raw)
				return decrypted as T
			} catch (ex) {
				console.error("Failed to decrypt", key, ex)
				return undefined as T
			}
		},

		async unset(ctx: Context, key: string) {
			deleteCookie(ctx, key)
		},

		async invalidate(subject: string) {
			const keys = await Array.fromAsync(Storage.scan(storage, ["oauth:refresh", subject]))
			for (const [key] of keys) {
				await Storage.remove(storage, key)
			}
		},

		storage
	}

	// Create main Hono app
	const app = new Hono<{ Variables: { authorization: AuthorizationState } }>()

	// Setup provider routes
	for (const [name, value] of Object.entries(input.providers)) {
		const route = new Hono<{ Variables: { provider: string } }>()

		route.use(async (c, next) => {
			c.set("provider", name)
			await next()
		})

		value.init(route as unknown as ProviderRoute, {
			name,
			...auth
		})

		app.route(`/${name}`, route)
	}

	// Register all handlers
	registerDiscoveryEndpoints(app, {
		allSigning,
		issuer,
		allSupportedScopes,
		claimsSupported
	})

	registerTokenEndpoint(app, {
		storage,
		generateTokens,
		ttl: {
			access: ttlAccess,
			refresh: ttlRefresh,
			refreshReuse: ttlRefreshReuse,
			refreshRetention: ttlRefreshRetention
		},
		auth,
		refresh: input.refresh,
		success: input.success,
		providers: input.providers,
		resolveSubject
	})

	registerAuthorizeEndpoint(app, {
		storage,
		allow,
		auth,
		ttlOauthState,
		ttl: { access: ttlAccess, refresh: ttlRefresh },
		select,
		providers: input.providers,
		start: input.start,
		sso: input.sso,
		refresh: input.refresh,
		generateTokens,
		resolveSubject,
		ssoUtils: { getSsoCookieName, deleteSsoCookie, setSsoCookie, acquireSsoLock }
	})

	registerUserEndpoints(app, {
		storage,
		signingKey,
		issuer,
		auth,
		sso: input.sso,
		ssoUtils: { getSsoCookieName, deleteSsoCookie }
	})

	registerRevokeEndpoint(app, {
		storage,
		sso: input.sso
	})

	// Error handling
	app.onError(async (err, c) => {
		console.error(err)
		if (err instanceof UnknownStateError) {
			return auth.forward(c, await error(err, c.req.raw))
		}

		try {
			const authorization = await getAuthorization(c)
			const url = new URL(authorization.redirect_uri!)
			const oauth =
				err instanceof OauthError ? err : new OauthError("server_error", err.message)
			url.searchParams.set("error", oauth.error)
			url.searchParams.set("error_description", oauth.description)
			if (authorization.state) {
				url.searchParams.set("state", authorization.state)
			}
			return c.redirect(url.toString())
		} catch {
			return c.json(
				{
					error: "server_error",
					error_description: err.message
				},
				500
			)
		}
	})

	return app
}
