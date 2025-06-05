import type { Context } from "hono"
import { deleteCookie, getCookie, setCookie } from "hono/cookie"
import { Hono } from "hono/tiny"
import type { StatusCode } from "hono/utils/http-status"
/**
 * The `issuer` create an OpentAuth server, a [Hono](https://hono.dev) app that's
 * designed to run anywhere.
 *
 * The `issuer` function requires a few things:
 *
 * ```ts title="issuer.ts"
 * import { issuer } from "@draftauth/core"
 *
 * const app = issuer({
 *   providers: { ... },
 *   storage,
 *   subjects,
 *   success: async (ctx, value, req, clientID) => { ... }
 * })
 * ```
 *
 * #### Add providers
 *
 * You start by specifying the auth providers you are going to use. Let's say you want your users
 * to be able to authenticate with GitHub and with their email and password.
 *
 * ```ts title="issuer.ts"
 * import { GithubProvider } from "@draftauth/core/provider/github"
 * import { PasswordProvider } from "@draftauth/core/provider/password"
 *
 * const app = issuer({
 *   providers: {
 *     github: GithubProvider({
 *       // ...
 *     }),
 *     password: PasswordProvider({
 *       // ...
 *     }),
 *   },
 * })
 * ```
 *
 * #### Handle success
 *
 * The `success` callback receives the payload when a user completes a provider's auth flow.
 *
 * ```ts title="issuer.ts"
 * const app = issuer({
 *   providers: { ... },
 *   subjects,
 *   async success(ctx, value, req, clientID) {
 *     let userID
 *
 *     if (clientID !== "allowed-client-id") {
 *       throw new Error("Unauthorized client")
 *     }
 *
 *     if (value.provider === "password") {
 *       console.log(value.email)
 *       userID = ... // lookup user or create them
 *     }
 *     if (value.provider === "github") {
 *       console.log(value.tokenset.access)
 *       userID = ... // lookup user or create them
 *     }
 *     return ctx.subject("user", {
 *       userID
 *     })
 *   }
 * })
 * ```
 *
 * Once complete, the `issuer` issues the access tokens that a client can use. The `ctx.subject`
 * call is what is placed in the access token as a JWT.
 *
 * #### Define subjects
 *
 * You define the shape of these in the `subjects` field.
 *
 * ```ts title="subjects.ts"
 * import { object, string } from "valibot"
 * import { createSubjects } from "@draftauth/core/subject"
 *
 * const subjects = createSubjects({
 *   user: object({
 *     userID: string()
 *   })
 * })
 * ```
 *
 * It's good to place this in a separate file since this'll be used in your client apps as well.
 *
 * ```ts title="issuer.ts"
 * import { subjects } from "./subjects.js"
 *
 * const app = issuer({
 *   providers: { ... },
 *   subjects,
 *   // ...
 * })
 * ```
 *
 * #### Deploy
 *
 * Since `issuer` is a Hono app, you can deploy it anywhere Hono supports.
 *
 * <Tabs>
 *   <TabItem label="Node">
 *   ```ts title="issuer.ts"
 *   import { serve } from "@hono/node-server"
 *
 *   serve(app)
 *   ```
 *   </TabItem>
 *   <TabItem label="Lambda">
 *   ```ts title="issuer.ts"
 *   import { handle } from "hono/aws-lambda"
 *
 *   export const handler = handle(app)
 *   ```
 *   </TabItem>
 *   <TabItem label="Bun">
 *   ```ts title="issuer.ts"
 *   export default app
 *   ```
 *   </TabItem>
 *   <TabItem label="Workers">
 *   ```ts title="issuer.ts"
 *   export default app
 *   ```
 *   </TabItem>
 * </Tabs>
 *
 * @packageDocumentation
 */
import type { Provider, ProviderOptions, ProviderRoute } from "./provider/provider"
import type { SubjectPayload, SubjectSchema } from "./subject"

/**
 * Sets the subject payload in the JWT token and returns the response.
 *
 * ```ts
 * ctx.subject("user", {
 *   userID
 * })
 * ```
 */
export interface OnSuccessResponder<T extends { type: string; properties: unknown }> {
	/**
	 * The `type` is the type of the subject, that was defined in the `subjects` field.
	 *
	 * The `properties` are the properties of the subject. This is the shape of the subject that
	 * you defined in the `subjects` field.
	 */
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
 * @internal
 */
export interface AuthorizationState {
	redirect_uri: string
	response_type: string
	state: string
	client_id: string
	audience?: string
	scopes?: string[]
	pkce?: {
		challenge: string
		method: "S256"
	}
}

/**
 * @internal
 */
export type Prettify<T> = {
	[K in keyof T]: T[K]
} & {}

import { cors } from "hono/cors"
import type { CookieOptions } from "hono/utils/cookie"
import { CompactEncrypt, SignJWT, compactDecrypt, jwtVerify } from "jose"
import { type AllowCheckInput, defaultAllowCheck } from "./allow"
import {
	MissingParameterError,
	OauthError,
	UnauthorizedClientError,
	UnknownStateError
} from "./error"
import { encryptionKeys, signingKeys } from "./keys"
import { validatePKCE } from "./pkce"
import { parseScopes, validateScopes } from "./scopes"
import { Storage, type StorageAdapter } from "./storage/storage"
import { type Theme, setTheme } from "./themes/theme"
import { Select } from "./ui/select"
import { getRelativeUrl, lazy } from "./util"

const DEFAULT_SSO_COOKIE_NAME_SECURE = "__Host-draftauth-sso"
const DEFAULT_SSO_COOKIE_NAME_INSECURE = "draftauth-sso"
const DEFAULT_SSO_SESSION_TTL_SECONDS = 60 * 60 * 24 * 7

/**
 * @interface SsoSessionData
 * @description Data stored for the central SSO session on the server-side.
 * @internal
 */
export interface SsoSessionData<T = string> {
	/** The unique identifier of the user. */
	userId: string
	/** The type of the subject (e.g., "user"). */
	subjectType: T
	/** User's email, stored for convenience. */
	email?: string
	/** Timestamp (ms) of when this SSO session was initiated. */
	authenticatedAt: number
	/** Timestamp (ms) of when this SSO session data should expire in storage. */
	expiresAt: number
	/** The resolved subject string for token invalidation */
	resolvedSubject: string
}

/**
 * @interface SsoLockMap
 * @description Map to store SSO operation locks to prevent race conditions
 * @internal
 */
interface SsoLockMap {
	[sessionId: string]: Promise<unknown>
}

export interface IssuerInput<
	Providers extends Record<string, Provider<unknown>>,
	Subjects extends SubjectSchema,
	Result = {
		[key in keyof Providers]: Prettify<
			{
				provider: key
			} & (Providers[key] extends Provider<infer T> ? T : Record<string, unknown>)
		>
	}[keyof Providers]
> {
	/**
	 * Callback to control refresh token usage.
	 *
	 * This allows you to implement custom logic for token refresh,
	 * including dynamic content in JWTs and refresh token revocation.
	 *
	 * The callback is called whenever a refresh token is used to obtain new access tokens.
	 * You can use this to:
	 * - Check if the user is still active/valid
	 * - Update JWT claims with fresh data from your database
	 * - Revoke tokens by returning `undefined`
	 * - Update scopes or other token metadata
	 *
	 * @example
	 * ```ts
	 * {
	 *   refresh: async (payload, req) => {
	 *     // Check if user is still active
	 *     const user = await getUserBySubject(payload.subject)
	 *     if (!user || !user.active) {
	 *       return undefined // Revoke the token
	 *     }
	 *
	 *     // Return updated payload with fresh data
	 *     return {
	 *       type: payload.type,
	 *       properties: {
	 *         userID: user.id,
	 *         role: user.role, // Updated role
	 *         permissions: user.permissions, // Updated permissions
	 *         lastLogin: new Date().toISOString()
	 *       },
	 *       scopes: user.scopes // Updated scopes
	 *     }
	 *   }
	 * }
	 * ```
	 *
	 * @param payload - The current token payload being refreshed
	 * @param req - The incoming HTTP request
	 * @returns Updated payload or `undefined` to revoke the token
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
	/**
	 * The shape of the subjects that you want to return.
	 *
	 * @example
	 *
	 * ```ts title="issuer.ts"
	 * import { object, string } from "valibot"
	 * import { createSubjects } from "@draftauth/core/subject"
	 *
	 * issuer({
	 *   subjects: createSubjects({
	 *     user: object({
	 *       userID: string()
	 *     })
	 *   })
	 *   // ...
	 * })
	 * ```
	 */
	subjects: Subjects
	/**
	 * The storage adapter that you want to use.
	 *
	 * @example
	 * ```ts title="issuer.ts"
	 * import { DynamoStorage } from "@draftauth/core/storage/dynamo"
	 *
	 * issuer({
	 *   storage: DynamoStorage()
	 *   // ...
	 * })
	 * ```
	 */
	storage: StorageAdapter
	/**
	 * The providers that you want your Draft Auth server to support.
	 *
	 * @example
	 *
	 * ```ts title="issuer.ts"
	 * import { GithubProvider } from "@draftauth/core/provider/github"
	 *
	 * issuer({
	 *   providers: {
	 *     github: GithubProvider()
	 *   }
	 * })
	 * ```
	 *
	 * The key is just a string that you can use to identify the provider. It's passed back to
	 * the `success` callback.
	 *
	 * You can also specify multiple providers.
	 *
	 * ```ts
	 * {
	 *   providers: {
	 *     github: GithubProvider(),
	 *     google: GoogleProvider()
	 *   }
	 * }
	 * ```
	 */
	providers: Providers
	/**
	 * Array containing a list of the OAuth 2.0 [RFC6749] "scope" values that this authorization server advertises.
	 *
	 * @example
	 * ```ts
	 * {
	 *   scopes_supported: ["read", "write"]
	 * }
	 * ```
	 */
	scopes_supported?: string[]

	/**
	 * The theme you want to use for the UI.
	 *
	 * This includes the UI the user sees when selecting a provider. And the `PasswordUI` and
	 * `CodeUI` that are used by the `PasswordProvider` and `CodeProvider`.
	 *
	 * @example
	 * ```ts title="issuer.ts"
	 * import { THEME_SST } from "@draftauth/core/ui/theme"
	 *
	 * issuer({
	 *   theme: THEME_SST
	 *   // ...
	 * })
	 * ```
	 *
	 * Or define your own.
	 *
	 * ```ts title="issuer.ts"
	 * import type { Theme } from "@draftauth/core/ui/theme"
	 *
	 * const MY_THEME: Theme = {
	 *   // ...
	 * }
	 *
	 * issuer({
	 *   theme: MY_THEME
	 *   // ...
	 * })
	 * ```
	 */
	theme?: Theme
	/**
	 * Set the TTL, in seconds, for access and refresh tokens.
	 *
	 * @example
	 * ```ts
	 * {
	 *   ttl: {
	 *     access: 60 * 60 * 24 * 30,
	 *     refresh: 60 * 60 * 24 * 365
	 *   }
	 * }
	 * ```
	 */
	ttl?: {
		/**
		 * Interval in seconds where the access token is valid.
		 * @default 30d
		 */
		access?: number
		/**
		 * Interval in seconds where the refresh token is valid.
		 * @default 1y
		 */
		refresh?: number
		/**
		 * Interval in seconds where refresh token reuse is allowed. This helps mitigrate
		 * concurrency issues.
		 * @default 60s
		 */
		reuse?: number
		/**
		 * Interval in seconds to retain refresh tokens for reuse detection.
		 * @default 0s
		 */
		retention?: number
		/**
		 * Time-to-live in seconds for the central SSO session and its cookie.
		 * @default 7 days
		 */
		ssoSessionSeconds?: number
	}
	sso?: {
		/**
		 * @property Globally enables or disables Single Sign-On functionality.
		 * @default false
		 */
		enabled?: boolean
		/**
		 * @property The name of the SSO session cookie.
		 * If not provided, will use "__Host-draftauth-sso" for HTTPS and "draftauth-sso" for HTTP.
		 */
		cookieName?: string
		/**
		 * @property Default URL to redirect to after a central logout from the issuer.
		 * Client applications can override this by providing a validated `post_logout_redirect_uri`.
		 */
		postLogoutRedirectUri?: string
		/**
		 * @property List of allowed hosts for logout redirect URIs.
		 */
		allowedLogoutHosts?: string[]
		/**
		 * @property Domain for the SSO cookie (for cross-subdomain SSO)
		 * @example ".draftauth.com.br" for SSO between api.draftauth.com.br and draftauth.com.br
		 */
		cookieDomain?: string
		/**
		 * @property Force secure cookies even if HTTPS detection fails
		 * Useful when behind proxies/load balancers that terminate SSL
		 * @default false
		 */
		forceSecure?: boolean
		/**
		 * @callback isSsoUserStillValid
		 * @description Optional callback to perform a live check if the user identified by the SSO session
		 * is still valid (e.g., not disabled, not locked) before proceeding with SSO for a new client application.
		 * @param {string} userId - The user ID from the SSO session.
		 * @param {SsoSessionData} ssoSessionData - The full data of the SSO session.
		 * @param {Request} req - The incoming Hono request to the /authorize endpoint.
		 * @returns {Promise<boolean>} True if the user is still valid for SSO, false to terminate SSO session.
		 */
		isSsoUserStillValid?: (
			userId: string,
			ssoSessionData: SsoSessionData<SubjectPayload<Subjects>["type"]>,
			req: Request
		) => Promise<boolean>
		/**
		 * @callback getSsoUserProperties
		 * @description Optional callback to fetch fresh or application-scoped properties for a user
		 * during an SSO flow to a new client application. This is called after the SSO session
		 * is validated and the client application is allowed.
		 * The returned properties will be used to mint the token for the client application.
		 * If not provided, properties from the original SSO session establishment (or a minimal set like id/email)
		 * might be used, or it could fall back to using the main `refresh` (for claims) callback logic if adaptable.
		 * @param {string} userId - The user ID from the SSO session.
		 * @param {SsoSessionData} ssoSessionData - The full data of the SSO session.
		 * @param {Request} req - The incoming Hono request to the /authorize endpoint.
		 * @param {string} clientID - The clientID of the application requesting authorization via SSO.
		 * @returns {Promise<Record<string, unknown>>} The properties to be included in the new token for the client app.
		 */
		getSsoUserProperties?: (
			userId: string,
			ssoSessionData: SsoSessionData<SubjectPayload<Subjects>["type"]>,
			req: Request,
			clientID: string
		) => Promise<Record<string, unknown>>
	}
	/**
	 * Optionally, configure the UI that's displayed when the user visits the root URL of the
	 * of the Draft Auth server.
	 *
	 * ```ts title="issuer.ts"
	 * import { Select } from "@draftauth/core/ui/select"
	 *
	 * issuer({
	 *   select: Select({
	 *     providers: {
	 *       github: { hide: true },
	 *       google: { display: "Google" }
	 *     }
	 *   })
	 *   // ...
	 * })
	 * ```
	 *
	 * @default Select()
	 */
	select?(providers: Record<string, string>, req: Request): Promise<Response>
	/**
	 * @internal
	 */
	start?(req: Request): Promise<void>
	/**
	 * The success callback that's called when the user completes the flow.
	 *
	 * This is called after the user has been redirected back to your app after the OAuth flow.
	 *
	 * @example
	 * ```ts
	 * {
	 *   success: async (ctx, value, req, clientID) => {
	 *     let userID
	 *
	 *     if (clientID !== "allowed-client-id") {
	 *       throw new Error("Unauthorized client")
	 *     }
	 *
	 *     if (value.provider === "password") {
	 *       console.log(value.email)
	 *       userID = ... // lookup user or create them
	 *     }
	 *     if (value.provider === "github") {
	 *       console.log(value.tokenset.access)
	 *       userID = ... // lookup user or create them
	 *     }
	 *     return ctx.subject("user", {
	 *       userID
	 *     })
	 *   },
	 *   // ...
	 * }
	 * ```
	 */
	success(
		response: OnSuccessResponder<SubjectPayload<Subjects>>,
		input: Result,
		req: Request,
		clientID: string
	): Promise<Response>
	/**
	 * @internal
	 */
	error?(error: UnknownStateError, req: Request): Promise<Response>
	/**
	 * Override the logic for whether a client request is allowed to call the issuer.
	 * If not provided, `defaultAllowCheck` will be used.
	 * To extend the default behavior, import and call `defaultAllowCheck` within your custom function.
	 *
	 * By default, it uses the following:
	 *
	 * - Allow if the `redirectURI` is localhost.
	 * - Compare `redirectURI` to the request's hostname or the `x-forwarded-host` header. If they
	 *   are from the same sub-domain level, then allow.
	 *
	 * @example
	 * ```ts
	 * {
	 *   allow: async (input, req) => {
	 *     // Allow all clients
	 *     return true
	 *   }
	 * }
	 * ```
	 */
	allow?(input: AllowCheckInput, req: Request): Promise<boolean>
}

/**
 * Create an Draft Auth server, a Hono app.
 */
export const issuer = <
	Providers extends Record<string, Provider<unknown>>,
	Subjects extends SubjectSchema,
	Result = {
		[key in keyof Providers]: Prettify<
			{
				provider: key
			} & (Providers[key] extends Provider<infer T> ? T : Record<string, unknown>)
		>
	}[keyof Providers]
>(
	input: IssuerInput<Providers, Subjects, Result>
) => {
	const error =
		input.error ??
		((err) => {
			return new Response(err.message, {
				status: 400,
				headers: {
					"Content-Type": "text/plain"
				}
			})
		})
	const ttlAccess = input.ttl?.access ?? 60 * 60 * 24 * 30
	const ttlRefresh = input.ttl?.refresh ?? 60 * 60 * 24 * 365
	const ttlRefreshReuse = input.ttl?.reuse ?? 60
	const ttlRefreshRetention = input.ttl?.retention ?? 0
	if (input.theme) {
		setTheme(input.theme)
	}

	const select = lazy(() => input.select ?? Select())
	const allow = lazy(() => input.allow ?? defaultAllowCheck)

	const storage = input.storage
	const allSigning = lazy(() => signingKeys(storage).then((keys) => keys))
	const allEncryption = lazy(() => encryptionKeys(storage))
	const signingKey = lazy(() => allSigning().then((all) => all[0]))
	const encryptionKey = lazy(() => allEncryption().then((all) => all[0]))

	const ssoEnabled = input.sso?.enabled === true
	const ssoSessionTtlToUse = input.ttl?.ssoSessionSeconds ?? DEFAULT_SSO_SESSION_TTL_SECONDS
	const allowedLogoutHosts = input.sso?.allowedLogoutHosts ?? ["localhost"]

	const ssoLocks: SsoLockMap = {}

	const isHttpsRequest = (ctx: Context): boolean => {
		if (input.sso?.forceSecure) {
			return true
		}

		if (ctx.req.url.startsWith("https://")) {
			return true
		}

		const xForwardedProto = ctx.req.header("x-forwarded-proto")
		const xForwardedScheme = ctx.req.header("x-forwarded-scheme")
		const xScheme = ctx.req.header("x-scheme")

		return xForwardedProto === "https" || xForwardedScheme === "https" || xScheme === "https"
	}

	const getSsoCookieName = (ctx: Context): string => {
		if (input.sso?.cookieName) {
			return input.sso.cookieName
		}

		const isHttps = isHttpsRequest(ctx)
		return isHttps ? DEFAULT_SSO_COOKIE_NAME_SECURE : DEFAULT_SSO_COOKIE_NAME_INSECURE
	}

	const validateLogoutRedirectUri = (uri: string): boolean => {
		try {
			const url = new URL(uri)
			return allowedLogoutHosts.some(
				(host) => url.hostname === host || url.hostname.endsWith(`.${host}`)
			)
		} catch {
			return false
		}
	}

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

	const setSsoCookie = (ctx: Context, sessionId: string): void => {
		const isHttps = isHttpsRequest(ctx)
		const cookieName = getSsoCookieName(ctx)

		const cookieOptions: CookieOptions = {
			path: "/",
			httpOnly: true,
			secure: isHttps,
			sameSite: isHttps ? "None" : "Lax",
			maxAge: ssoSessionTtlToUse
		}

		if (input.sso?.cookieDomain) {
			cookieOptions.domain = input.sso.cookieDomain
		}

		setCookie(ctx, cookieName, sessionId, cookieOptions)
	}

	const deleteSsoCookie = (ctx: Context): void => {
		const cookieName = getSsoCookieName(ctx)
		const isHttps = isHttpsRequest(ctx)

		const cookieOptions: Parameters<typeof deleteCookie>[2] = {
			path: "/",
			httpOnly: true,
			secure: isHttps,
			sameSite: "Lax"
		}

		if (input.sso?.cookieDomain) {
			cookieOptions.domain = input.sso.cookieDomain
		}

		deleteCookie(ctx, cookieName, cookieOptions)
	}

	const cleanupExpiredSsoSessions = async (): Promise<void> => {
		try {
			const keys = await Array.fromAsync(Storage.scan(storage, ["sso:session"]))
			const now = Date.now()

			for (const [key] of keys) {
				try {
					const session = await Storage.get<SsoSessionData>(storage, key)
					if (session && session.expiresAt < now) {
						await Storage.remove(storage, key)
					}
				} catch (err) {
					console.error("Error cleaning up SSO session:", err)
				}
			}
		} catch (err) {
			console.error("Error during SSO cleanup:", err)
		}
	}

	if (ssoEnabled) {
		setInterval(cleanupExpiredSsoSessions, 60 * 60 * 1000)
	}

	const auth: Omit<ProviderOptions<unknown>, "name"> = {
		async success(ctx: Context, properties: unknown, successOpts) {
			const authorization = await getAuthorization(ctx)
			return await input.success(
				{
					async subject(type, properties, subjectOpts) {
						const subject = subjectOpts?.subject
							? subjectOpts.subject
							: await resolveSubject(type, properties)
						await successOpts?.invalidate?.(await resolveSubject(type, properties))

						if (ssoEnabled) {
							const userIdForSso = (properties as { id?: string }).id
							const userEmailForSso = (properties as { email?: string }).email

							if (userIdForSso) {
								const ssoSessionId = crypto.randomUUID()
								const ssoExpiresAt = Date.now() + ssoSessionTtlToUse * 1000
								const ssoSessionPayload: SsoSessionData = {
									userId: userIdForSso,
									email: userEmailForSso,
									subjectType: type,
									authenticatedAt: Date.now(),
									expiresAt: ssoExpiresAt,
									resolvedSubject: subject
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

						if (authorization.response_type === "token") {
							const location = new URL(authorization.redirect_uri)
							const tokens = await generateTokens(ctx, {
								subject,
								type: type as string,
								properties,
								clientID: authorization.client_id,
								scopes: authorization.scopes,
								ttl: {
									access: subjectOpts?.ttl?.access ?? ttlAccess,
									refresh: subjectOpts?.ttl?.refresh ?? ttlRefresh
								}
							})
							location.hash = new URLSearchParams({
								access_token: tokens.access,
								refresh_token: tokens.refresh,
								state: authorization.state || ""
							}).toString()
							await auth.unset(ctx, "authorization")
							return ctx.redirect(location.toString(), 302)
						}
						if (authorization.response_type === "code") {
							const code = crypto.randomUUID()
							await Storage.set(
								storage,
								["oauth:code", code],
								{
									type,
									properties,
									subject,
									redirectURI: authorization.redirect_uri,
									clientID: authorization.client_id,
									pkce: authorization.pkce,
									scopes: authorization.scopes,
									ttl: {
										access: subjectOpts?.ttl?.access ?? ttlAccess,
										refresh: subjectOpts?.ttl?.refresh ?? ttlRefresh
									}
								},
								60
							)
							const location = new URL(authorization.redirect_uri)
							location.searchParams.set("code", code)
							location.searchParams.set("state", authorization.state || "")
							await auth.unset(ctx, "authorization")
							return ctx.redirect(location.toString(), 302)
						}
						throw new OauthError(
							"invalid_request",
							`Unsupported response_type: ${authorization.response_type}`
						)
					}
				},
				{
					provider: ctx.get("provider"),
					...(properties && typeof properties === "object" ? properties : {})
				} as Result,
				ctx.req.raw,
				authorization.client_id
			)
		},
		forward(ctx, response) {
			return ctx.newResponse(
				response.body,
				response.status as StatusCode,
				Object.fromEntries(Array.from(response.headers.entries()))
			)
		},
		async set(ctx, key, maxAge, value) {
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
				console.error("failed to decrypt", key, ex)
				return undefined as T
			}
		},
		async unset(ctx: Context, key: string) {
			deleteCookie(ctx, key)
		},
		async invalidate(subject: string) {
			// Resolve the scan in case modifications interfere with iteration
			const keys = await Array.fromAsync(Storage.scan(storage, ["oauth:refresh", subject]))
			for (const [key] of keys) {
				await Storage.remove(storage, key)
			}
		},
		storage
	}

	const getAuthorization = async (ctx: Context) => {
		const match = (await auth.get(ctx, "authorization")) || ctx.get("authorization")
		if (!match) throw new UnknownStateError()
		return match as AuthorizationState
	}

	const encrypt = async (value: unknown) => {
		const key = await encryptionKey()
		if (!key) {
			throw new Error("Encryption key not available")
		}
		return await new CompactEncrypt(new TextEncoder().encode(JSON.stringify(value)))
			.setProtectedHeader({ alg: "RSA-OAEP-512", enc: "A256GCM" })
			.encrypt(key.public)
	}

	const resolveSubject = async (type: string, properties: unknown) => {
		const jsonString = JSON.stringify(properties)
		const encoder = new TextEncoder()
		const data = encoder.encode(jsonString)
		const hashBuffer = await crypto.subtle.digest("SHA-1", data)
		const hashArray = Array.from(new Uint8Array(hashBuffer))
		const hashHex = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("")
		return `${type}:${hashHex.slice(0, 16)}`
	}

	const generateTokens = async (
		ctx: Context,
		value: {
			type: string
			properties: unknown
			subject: string
			clientID: string
			ttl: {
				access: number
				refresh: number
			}
			timeUsed?: number
			nextToken?: string
			scopes?: string[]
		},
		opts?: {
			generateRefreshToken?: boolean
		}
	) => {
		const refreshToken = value.nextToken ?? crypto.randomUUID()
		if (opts?.generateRefreshToken ?? true) {
			/**
			 * Generate and store the next refresh token after the one we are currently returning.
			 * Reserving these in advance avoids concurrency issues with multiple refreshes.
			 * Similar treatment should be given to other values that may have race conditions,
			 * for example if a jti claim was added to the access token.
			 */
			const { timeUsed, ...refreshValueWithoutTimeUsed } = value
			const refreshValue = {
				...refreshValueWithoutTimeUsed,
				nextToken: crypto.randomUUID()
			}

			await Storage.set(
				storage!,
				["oauth:refresh", value.subject, refreshToken],
				refreshValue,
				value.ttl.refresh
			)
		}

		const accessTimeUsed = Math.floor((value.timeUsed ?? Date.now()) / 1000)
		const signingKeyData = await signingKey()
		if (!signingKeyData) {
			throw new Error("Signing key not available")
		}

		return {
			access: await new SignJWT({
				mode: "access",
				type: value.type,
				properties: value.properties,
				aud: value.clientID,
				iss: issuer(ctx),
				sub: value.subject,
				scopes: value.scopes
			})
				.setIssuedAt(accessTimeUsed)
				.setExpirationTime(Math.floor(accessTimeUsed + value.ttl.access))
				.setProtectedHeader({
					alg: signingKeyData.alg,
					kid: signingKeyData.id,
					typ: "JWT"
				})
				.sign(signingKeyData.private),
			expiresIn: Math.floor(accessTimeUsed + value.ttl.access - Date.now() / 1000),
			refresh: [value.subject, refreshToken].join(":")
		}
	}

	const decrypt = async (value: string) => {
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

	const issuer = (ctx: Context) => {
		return new URL(getRelativeUrl(ctx, "/")).origin
	}

	const app = new Hono<{
		Variables: {
			authorization: AuthorizationState
		}
	}>()

	for (const [name, value] of Object.entries(input.providers)) {
		const route = new Hono<{
			Variables: {
				provider: string
			}
		}>()

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

	app.get(
		"/.well-known/jwks.json",
		cors({
			origin: "*",
			allowHeaders: ["*"],
			allowMethods: ["GET"],
			credentials: false
		}),
		async (c) => {
			const all = await allSigning()
			return c.json({
				keys: all.map((item) => ({
					...item.jwk,
					alg: item.alg,
					exp: item.expired ? Math.floor(item.expired.getTime() / 1000) : undefined
				}))
			})
		}
	)

	app.get(
		"/.well-known/oauth-authorization-server",
		cors({
			origin: "*",
			allowHeaders: ["*"],
			allowMethods: ["GET"],
			credentials: false
		}),
		async (c) => {
			const iss = issuer(c)
			return c.json({
				issuer: iss,
				authorization_endpoint: `${iss}/authorize`,
				token_endpoint: `${iss}/token`,
				revocation_endpoint: `${iss}/revoke`,
				jwks_uri: `${iss}/.well-known/jwks.json`,
				response_types_supported: ["code", "token"],
				scopes_supported: input.scopes_supported,
				revocation_endpoint_auth_methods_supported: ["none"]
			})
		}
	)

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

			if (grantType === "authorization_code") {
				const code = form.get("code")
				if (!code)
					return c.json(
						{
							error: "invalid_request",
							error_description: "Missing code"
						},
						400
					)
				const key = ["oauth:code", code.toString()]
				const payload = await Storage.get<{
					type: string
					properties: unknown
					clientID: string
					redirectURI: string
					subject: string
					scopes?: string[]
					ttl: {
						access: number
						refresh: number
					}
					pkce?: AuthorizationState["pkce"]
				}>(storage, key)
				if (!payload) {
					return c.json(
						{
							error: "invalid_grant",
							error_description: "Authorization code has been used or expired"
						},
						400
					)
				}

				if (payload.redirectURI !== form.get("redirect_uri")) {
					return c.json(
						{
							error: "invalid_redirect_uri",
							error_description: "Redirect URI mismatch"
						},
						400
					)
				}
				if (payload.clientID !== form.get("client_id")) {
					return c.json(
						{
							error: "unauthorized_client",
							error_description: "Client is not authorized to use this authorization code"
						},
						403
					)
				}

				if (payload.pkce) {
					const codeVerifier = form.get("code_verifier")?.toString()
					if (!codeVerifier)
						return c.json(
							{
								error: "invalid_grant",
								error_description: "Missing code_verifier"
							},
							400
						)

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
				payload.scopes = validateScopes(scope, payload.scopes)
				const tokens = await generateTokens(c, payload)
				await Storage.remove(storage, key)
				return c.json({
					access_token: tokens.access,
					expires_in: tokens.expiresIn,
					refresh_token: tokens.refresh,
					scope: payload.scopes?.join(" ")
				})
			}

			if (grantType === "refresh_token") {
				const refreshToken = form.get("refresh_token")
				if (!refreshToken)
					return c.json(
						{
							error: "invalid_request",
							error_description: "Missing refresh_token"
						},
						400
					)
				const splits = refreshToken.toString().split(":")
				const token = splits.pop()!
				const subject = splits.join(":")
				const key = ["oauth:refresh", subject, token]
				const payload = await Storage.get<{
					type: string
					properties: unknown
					clientID: string
					subject: string
					scopes?: string[]
					ttl: {
						access: number
						refresh: number
					}
					nextToken: string
					timeUsed?: number
				}>(storage, key)
				if (!payload) {
					return c.json(
						{
							error: "invalid_grant",
							error_description: "Refresh token has been used or expired"
						},
						400
					)
				}

				if (input.refresh) {
					try {
						const refreshResult = await input.refresh(
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

				const generateRefreshToken = !payload.timeUsed
				if (ttlRefreshReuse <= 0) {
					// no reuse interval, remove the refresh token immediately
					await Storage.remove(storage, key)
				} else if (!payload.timeUsed) {
					payload.timeUsed = Date.now()
					await Storage.set(storage, key, payload, ttlRefreshReuse + ttlRefreshRetention)
				} else if (Date.now() > payload.timeUsed + ttlRefreshReuse * 1000) {
					// token was reused past the allowed interval
					await auth.invalidate(subject)
					return c.json(
						{
							error: "invalid_grant",
							error_description: "Refresh token has been used or expired"
						},
						400
					)
				}
				payload.scopes = validateScopes(scope, payload.scopes)
				const tokens = await generateTokens(c, payload, {
					generateRefreshToken
				})
				return c.json({
					access_token: tokens.access,
					refresh_token: tokens.refresh,
					expires_in: tokens.expiresIn,
					scope: payload.scopes?.join(" ")
				})
			}

			if (grantType === "client_credentials") {
				const provider = form.get("provider")
				if (!provider) return c.json({ error: "missing `provider` form value" }, 400)
				const match = input.providers[provider.toString()]
				if (!match) return c.json({ error: "invalid `provider` query parameter" }, 400)
				if (!match.client)
					return c.json({ error: "this provider does not support client_credentials" }, 400)
				const clientID = form.get("client_id")
				const clientSecret = form.get("client_secret")
				if (!clientID) return c.json({ error: "missing `client_id` form value" }, 400)
				if (!clientSecret) return c.json({ error: "missing `client_secret` form value" }, 400)

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

				return input.success(
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
							return c.json({
								access_token: tokens.access,
								refresh_token: tokens.refresh
							})
						}
					},
					{
						provider: provider.toString(),
						...(response && typeof response === "object" ? response : {})
					} as Result,
					c.req.raw,
					clientID.toString()
				)
			}

			throw new Error("Invalid grant_type")
		}
	)

	app.get("/authorize", async (c) => {
		const provider = c.req.query("provider")
		const response_type = c.req.query("response_type")
		const redirect_uri = c.req.query("redirect_uri")
		const state = c.req.query("state")
		const client_id = c.req.query("client_id")
		const audience = c.req.query("audience")
		const code_challenge = c.req.query("code_challenge")
		const code_challenge_method = c.req.query("code_challenge_method")
		const scope = c.req.query("scope")
		const authorization: AuthorizationState = {
			response_type,
			redirect_uri,
			state,
			client_id,
			audience,
			scopes: parseScopes(scope),
			pkce:
				code_challenge && code_challenge_method
					? {
							challenge: code_challenge,
							method: code_challenge_method
						}
					: undefined
		} as AuthorizationState
		c.set("authorization", authorization)

		if (ssoEnabled) {
			const ssoCookieName = getSsoCookieName(c)
			const ssoSessionIdFromCookie = getCookie(c, ssoCookieName)
			if (ssoSessionIdFromCookie) {
				const ssoResult = await acquireSsoLock(ssoSessionIdFromCookie, async () => {
					const ssoSessionKey = ["sso:session", ssoSessionIdFromCookie]
					let ssoSessionData = await Storage.get<SsoSessionData>(storage, ssoSessionKey)

					let isSsoSessionStructurallyValid =
						ssoSessionData?.userId && ssoSessionData.expiresAt > Date.now()

					if (isSsoSessionStructurallyValid && input.sso?.isSsoUserStillValid) {
						try {
							isSsoSessionStructurallyValid = await input.sso.isSsoUserStillValid(
								ssoSessionData!.userId,
								ssoSessionData!,
								c.req.raw
							)
						} catch (error) {
							isSsoSessionStructurallyValid = false
						}

						if (!isSsoSessionStructurallyValid) {
							await Storage.remove(storage, ssoSessionKey)
							deleteSsoCookie(c)
							ssoSessionData = null
						}
					}

					if (isSsoSessionStructurallyValid && ssoSessionData) {
						if (!client_id || !redirect_uri || !response_type) {
							throw new MissingParameterError("client_id, redirect_uri, or response_type")
						}
						if (
							!(await allow()(
								{ clientID: client_id, redirectURI: redirect_uri, audience },
								c.req.raw
							))
						) {
							throw new UnauthorizedClientError(client_id, redirect_uri)
						}

						const authorizationForThisApp: AuthorizationState = {
							client_id,
							redirect_uri,
							response_type,
							state: state as string,
							scopes: parseScopes(scope),
							pkce:
								code_challenge && code_challenge_method
									? { challenge: code_challenge, method: code_challenge_method as "S256" }
									: undefined,
							audience
						}
						await auth.set(c, "authorization", 60 * 5, authorizationForThisApp)
						c.set("authorization", authorizationForThisApp)

						let finalSubjectProperties: Record<string, unknown> = {
							id: ssoSessionData.userId,
							email: ssoSessionData.email
						}
						let finalScopes = authorizationForThisApp.scopes

						if (input.sso?.getSsoUserProperties) {
							try {
								finalSubjectProperties = await input.sso.getSsoUserProperties(
									ssoSessionData.userId,
									ssoSessionData,
									c.req.raw,
									client_id
								)
							} catch (error) {
								console.error("Error getting SSO user properties:", error)
							}
						} else if (input.refresh) {
							try {
								const refreshedClaims = await input.refresh(
									{
										type: ssoSessionData.subjectType,
										properties: { id: ssoSessionData.userId, email: ssoSessionData.email },
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
							} catch (error) {
								console.error("Error refreshing SSO claims:", error)
							}
						}

						const resolvedSsoUserJwtSubject =
							ssoSessionData.resolvedSubject ||
							(await resolveSubject(ssoSessionData.subjectType, finalSubjectProperties))

						if (authorizationForThisApp.response_type === "code") {
							const code = crypto.randomUUID()
							await Storage.set(
								storage,
								["oauth:code", code],
								{
									type: ssoSessionData.subjectType,
									properties: finalSubjectProperties,
									subject: resolvedSsoUserJwtSubject,
									redirectURI: authorizationForThisApp.redirect_uri,
									clientID: authorizationForThisApp.client_id,
									pkce: authorizationForThisApp.pkce,
									scopes: finalScopes,
									ttl: { access: ttlAccess, refresh: ttlRefresh }
								},
								60
							)
							const location = new URL(authorizationForThisApp.redirect_uri)
							location.searchParams.set("code", code)
							if (authorizationForThisApp.state)
								location.searchParams.set("state", authorizationForThisApp.state)
							await auth.unset(c, "authorization")
							setSsoCookie(c, ssoSessionIdFromCookie)
							return c.redirect(location.toString(), 302)
						}
						throw new OauthError(
							"access_denied",
							`SSO flow for ${client_id} currently only supports 'code' response_type.`
						)
					}

					return null
				})

				if (ssoResult !== null) {
					return ssoResult as Response
				}
			}
		}

		if (!redirect_uri) {
			return c.text("Missing redirect_uri", { status: 400 })
		}

		if (!response_type) {
			throw new MissingParameterError("response_type")
		}

		if (!client_id) {
			throw new MissingParameterError("client_id")
		}

		if (input.start) {
			await input.start(c.req.raw)
		}

		if (
			!(await allow()(
				{
					clientID: client_id,
					redirectURI: redirect_uri,
					audience
				},
				c.req.raw
			))
		)
			throw new UnauthorizedClientError(client_id, redirect_uri)
		await auth.set(c, "authorization", 60 * 60 * 24, authorization)
		if (provider) return c.redirect(`/${provider}/authorize`)
		const providers = Object.keys(input.providers)
		if (providers.length === 1) return c.redirect(`/${providers[0]}/authorize`)
		return auth.forward(
			c,
			await select()(
				Object.fromEntries(
					Object.entries(input.providers).map(([key, value]) => [key, value.type])
				),
				c.req.raw
			)
		)
	})

	if (ssoEnabled) {
		app.get("/logout", async (c) => {
			const ssoCookieName = getSsoCookieName(c)
			const ssoSessionId = getCookie(c, ssoCookieName)
			if (ssoSessionId) {
				const ssoSessionKey = ["sso:session", ssoSessionId]
				const ssoSessionData = await Storage.get<SsoSessionData>(storage, ssoSessionKey)
				if (ssoSessionData) {
					await auth.invalidate(ssoSessionData.resolvedSubject)
				}
				await Storage.remove(storage, ssoSessionKey)
			}
			deleteSsoCookie(c)

			let redirectTo = c.req.query("post_logout_redirect_uri")
			if (redirectTo && validateLogoutRedirectUri(redirectTo)) {
				return c.redirect(redirectTo, 302)
			}

			redirectTo = input.sso?.postLogoutRedirectUri
			if (redirectTo) {
				return c.redirect(redirectTo, 302)
			}

			return c.html("<p>Logout bem-sucedido do Draft Auth.</p>")
		})
	}

	app.post(
		"/revoke",
		cors({
			origin: "*",
			allowHeaders: ["*"],
			allowMethods: ["POST"],
			credentials: false
		}),
		async (c) => {
			const form = await c.req.formData()
			const tokenParam = form.get("token")
			const tokenTypeHint = form.get("token_type_hint")
			const revokeAll = form.get("revoke_all") === "true"
			const clientIDParam = form.get("client_id")

			if (!tokenParam) {
				return c.newResponse(null, 200)
			}

			if (tokenTypeHint && tokenTypeHint.toString() !== "refresh_token") {
				return c.json(
					{
						error: "unsupported_token_type",
						error_description: "Revocation of access tokens is not supported"
					},
					400
				)
			}

			try {
				const token = tokenParam.toString()

				const splits = token.split(":")
				const tokenId = splits.pop()!
				const subject = splits.join(":")

				if (!subject || !tokenId) {
					return c.newResponse(null, 200)
				}

				const key = ["oauth:refresh", subject, tokenId]
				const payload = await Storage.get<{
					type: string
					properties: unknown
					clientID: string
					subject: string
					scopes?: string[]
					ttl: {
						access: number
						refresh: number
					}
					nextToken: string
					timeUsed?: number
				}>(storage, key)

				if (payload) {
					if (clientIDParam && payload.clientID !== clientIDParam.toString()) {
						return c.json(
							{
								error: "invalid_client",
								error_description: "Token does not belong to the specified client"
							},
							400
						)
					}

					await Storage.remove(storage, key)

					if (revokeAll) {
						const keys = await Array.fromAsync(
							Storage.scan(storage, ["oauth:refresh", subject])
						)
						await Promise.all(keys.map(([scanKey]) => Storage.remove(storage, scanKey)))
					}

					if (clientIDParam && !revokeAll) {
						const keys = await Array.fromAsync(
							Storage.scan(storage, ["oauth:refresh", subject])
						)

						for (const [scanKey] of keys) {
							const scanPayload = await Storage.get<{
								type: string
								properties: unknown
								clientID: string
								subject: string
								scopes?: string[]
								ttl: {
									access: number
									refresh: number
								}
								nextToken: string
								timeUsed?: number
							}>(storage, scanKey)

							if (scanPayload && scanPayload.clientID === clientIDParam.toString()) {
								await Storage.remove(storage, scanKey)
							}
						}
					}
				}

				return c.newResponse(null, 200)
			} catch (error) {
				console.error("Error revoking token:", error)
				return c.newResponse(null, 200)
			}
		}
	)

	app.get("/userinfo", async (c) => {
		const header = c.req.header("Authorization")

		if (!header) {
			return c.json(
				{
					error: "invalid_request",
					error_description: "Missing Authorization header"
				},
				400
			)
		}

		const [type, token] = header.split(" ")

		if (type !== "Bearer") {
			return c.json(
				{
					error: "invalid_request",
					error_description: "Missing or invalid Authorization header"
				},
				400
			)
		}

		if (!token) {
			return c.json(
				{
					error: "invalid_request",
					error_description: "Missing token"
				},
				400
			)
		}

		try {
			const signingKeyData = await signingKey()
			if (!signingKeyData) {
				return c.json({
					error: "invalid_token",
					error_description: "Signing key not available"
				})
			}

			const result = await jwtVerify<{
				mode: "access"
				type: string
				properties: unknown
			}>(token, signingKeyData.public, {
				issuer: issuer(c)
			})

			const subjectType = result.payload.type as keyof Subjects
			const subjectSchema = input.subjects[subjectType]
			if (!subjectSchema) {
				return c.json({
					error: "invalid_token",
					error_description: "Invalid subject type"
				})
			}

			const validated = await subjectSchema["~standard"].validate(result.payload.properties)

			if (!validated.issues && result.payload.mode === "access") {
				return c.json(validated.value as Record<string, unknown>)
			}

			return c.json({
				error: "invalid_token",
				error_description: "Invalid token"
			})
		} catch (error) {
			return c.json({
				error: "invalid_token",
				error_description: "Token verification failed"
			})
		}
	})

	app.onError(async (err, c) => {
		console.error(err)
		if (err instanceof UnknownStateError) {
			return auth.forward(c, await error(err, c.req.raw))
		}
		const authorization = await getAuthorization(c)
		const url = new URL(authorization.redirect_uri)
		const oauth = err instanceof OauthError ? err : new OauthError("server_error", err.message)
		url.searchParams.set("error", oauth.error)
		url.searchParams.set("error_description", oauth.description)
		return c.redirect(url.toString())
	})

	return app
}
