/**
 * Core issuer implementation integrating all handlers.
 * Main entry point that assembles the complete Draft Auth server.
 */
import { type Context, Hono } from "hono"
import { deleteCookie, getCookie, setCookie } from "hono/cookie"
import type { StatusCode } from "hono/utils/http-status"
import { CompactEncrypt, compactDecrypt, SignJWT } from "jose"
import { type AllowCheckInput, defaultAllowCheck } from "./allow"
import {
	type ClaimsConfiguration,
	createDefaultClaimsConfig,
	transformClaims,
	validateEssentialClaims
} from "./claims"
import { OauthError, UnknownStateError } from "./error"
import { registerAuthorizeEndpoint } from "./handlers/authorize"
import { registerDiscoveryEndpoints } from "./handlers/discovery"
import { registerRevokeEndpoint } from "./handlers/revoke"
import { registerTokenEndpoint } from "./handlers/token"
import { registerUserEndpoints } from "./handlers/user"
import { encryptionKeys, signingKeys } from "./keys"
import type { Provider, ProviderRoute } from "./provider/provider"
import { parseScopes } from "./scopes"
import { createSsoUtils, handleSsoSessionCreation, type SsoConfiguration } from "./sso"
import { Storage, type StorageAdapter } from "./storage/storage"
import type { SubjectPayload, SubjectSchema } from "./subject"
import { setTheme, type Theme } from "./themes/theme"
import type { AuthorizationState, TokenGenerationResult } from "./types"
import { Select } from "./ui/select"
import { getRelativeUrl, lazy } from "./util"

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
	sso?: SsoConfiguration
	/** Supported OAuth 2.0 scopes */
	scopes_supported?: string[]
	/** Claims configuration for OIDC token and UserInfo transformations */
	claims?: ClaimsConfiguration<SubjectPayload<Subjects>["properties"]>
	/** Provider selection UI function */
	select?(providers: Record<string, string>, req: Request): Promise<Response>
	/** Optional start callback */
	start?(req: Request): Promise<void>
	/** Error handling callback */
	error?(error: UnknownStateError, req: Request): Promise<Response>
	/** Client authorization check function */
	allow?(input: AllowCheckInput, req: Request): Promise<boolean>
	/**
	 * Refresh callback for updating user claims with full TypeScript autocomplete.
	 * Properties parameter is now strongly typed based on your subject schemas.
	 *
	 * @example
	 * ```typescript
	 * refresh: async (payload, req) => {
	 *   // payload.properties now has full autocomplete based on your subjects!
	 *   const user = await getUserBySubject(payload.subject)
	 *   if (!user || !user.active) {
	 *     return undefined // Revoke the token
	 *   }
	 *
	 *   return {
	 *     type: payload.type,
	 *     properties: {
	 *       userID: user.id,
	 *       role: user.role,        // ✅ TypeScript knows about these properties
	 *       permissions: user.permissions,
	 *       lastLogin: new Date().toISOString()
	 *     }
	 *   }
	 * }
	 * ```
	 */
	refresh?(
		payload: {
			type: SubjectPayload<Subjects>["type"]
			properties: SubjectPayload<Subjects>["properties"]
			subject: string
			clientID: string
			scopes?: string[]
		},
		req: Request
	): Promise<
		| {
				type: SubjectPayload<Subjects>["type"]
				properties: SubjectPayload<Subjects>["properties"]
				subject?: string
				scopes?: string[]
		  }
		| undefined
	>
}

/**
 * Determines if the incoming request is using HTTPS protocol.
 * Checks multiple proxy headers to handle load balancers and reverse proxies.
 *
 * @param ctx - Hono context containing request headers and URL
 * @returns True if request is HTTPS, false otherwise
 *
 * @example
 * ```ts
 * if (isHttpsRequest(ctx)) {
 *   setCookie(ctx, 'secure-cookie', value, { secure: true })
 * }
 * ```
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
	const ttlOauthState = input.ttl?.oauthState ?? 600

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
		const standardClaims: Record<string, unknown> = {
			iss: issuer(ctx),
			sub: payload.sub,
			aud: payload.aud,
			exp: now + 3600, // ID tokens expire in 1 hour
			iat: now,
			auth_time: payload.authTime,
			...(payload.sessionId && { sid: payload.sessionId }),
			...(payload.nonce && { nonce: payload.nonce })
		}

		// Transform claims using configuration or default behavior
		const claimsConfig = input.claims || createDefaultClaimsConfig()
		const transformContext = {
			clientID: payload.aud,
			scopes: payload.scopes,
			target: "id_token" as const,
			issuer: issuer(ctx),
			nonce: payload.nonce,
			sessionId: payload.sessionId,
			authTime: payload.authTime
		}

		const transformedClaims = await transformClaims(
			payload.properties,
			transformContext,
			claimsConfig
		)

		if (transformedClaims === null) {
			// Check if we have claims config with essential validation to get specific missing claims
			if (claimsConfig.essential) {
				const validationResult = validateEssentialClaims(
					payload.properties,
					claimsConfig.essential,
					transformContext
				)
				if (!validationResult.success) {
					throw new Error(
						`Essential claims validation failed for ID token. Missing: ${validationResult.missing.join(", ")}`
					)
				}
			}

			throw new Error(
				"Essential claims validation failed for ID token. Claims transformation returned null."
			)
		}

		// Merge standard claims with transformed claims
		// Standard claims take precedence to ensure OIDC compliance
		const finalClaims = {
			...transformedClaims,
			...standardClaims
		}

		const idTokenEssentialConfig = {
			required: ["sub", "iss", "aud", "exp", "iat"],
			strict: true
		}

		const idTokenValidation = validateEssentialClaims(
			finalClaims,
			idTokenEssentialConfig,
			transformContext
		)

		if (!idTokenValidation.success) {
			throw new Error(
				`Essential claims validation failed for ID token. Missing: ${idTokenValidation.missing.join(", ")}`
			)
		}

		return await new SignJWT(finalClaims)
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

		// Transform claims for access token as well
		const claimsConfig = input.claims || createDefaultClaimsConfig()
		const transformContext = {
			clientID: value.clientID,
			scopes: value.scopes || [],
			target: "access_token" as const,
			issuer: issuer(ctx)
		}

		const transformedClaimsResult = await transformClaims(
			value.properties,
			transformContext,
			claimsConfig
		)

		if (transformedClaimsResult === null) {
			// Check if we have claims config with essential validation to get specific missing claims
			if (claimsConfig.essential) {
				const validationResult = validateEssentialClaims(
					value.properties as Record<string, unknown>,
					claimsConfig.essential,
					transformContext
				)

				if (!validationResult.success) {
					throw new Error(
						`Essential claims validation failed for access token. Missing: ${validationResult.missing.join(", ")}`
					)
				}
			}

			throw new Error(
				"Essential claims validation failed for access token. Claims transformation returned null."
			)
		}

		// client must be present and non-empty
		if (!value.clientID || !value.clientID.trim()) {
			throw new Error("Invalid audience: client ID cannot be empty")
		}

		const accessPayload = {
			type: value.type,
			properties: transformedClaimsResult,
			sub: value.subject,
			aud: value.clientID,
			iss: issuer(ctx),
			exp: now + value.ttl.access,
			iat: now,
			mode: "access",
			scopes: value.scopes
		}

		const accessTokenEssentialConfig = {
			required: ["sub", "iss", "aud", "exp", "iat", "mode", "type"],
			strict: true
		}

		const accessTokenValidation = validateEssentialClaims(
			accessPayload,
			accessTokenEssentialConfig,
			transformContext
		)

		if (!accessTokenValidation.success) {
			throw new Error(
				`Essential claims validation failed for Access token. Missing: ${accessTokenValidation.missing.join(", ")}`
			)
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
			const currentProvider = ctx.get("provider") || "unknown"
			return await input.success(
				{
					async subject(type, properties, subjectOpts) {
						const subject = subjectOpts?.subject ?? (await resolveSubject(type, properties))
						await successOpts?.invalidate?.(subject)

						// Handle SSO session creation
						if (input.sso?.enabled) {
							await handleSsoSessionCreation(
								ctx,
								type as string,
								properties as Record<string, unknown>,
								subject,
								input.sso,
								storage,
								isHttpsRequest
							)
						}

						// Handle different response types
						if (authorization.response_type === "token") {
							const location = new URL(authorization.redirect_uri!)
							const scopes =
								parseScopes(authorization.scopes).length > 0
									? parseScopes(authorization.scopes)
									: ["openid"]
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
							scopes:
								parseScopes(authorization.scopes).length > 0
									? parseScopes(authorization.scopes)
									: ["openid"],
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
					provider: currentProvider,
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
			} catch {
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
		allSupportedScopes
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
		resolveSubject,
		claims: input.claims,
		issuer
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
		ssoUtils: createSsoUtils(input.sso || {}, isHttpsRequest)
	})

	registerUserEndpoints(app, {
		storage,
		signingKey,
		issuer,
		auth,
		sso: input.sso,
		ssoUtils: createSsoUtils(input.sso || {}, isHttpsRequest),
		claims: input.claims
	})

	registerRevokeEndpoint(app, {
		storage,
		sso: input.sso
	})

	// Error handling
	app.onError(async (err, c) => {
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
