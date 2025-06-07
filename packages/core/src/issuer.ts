import type { Context } from "hono"
import { deleteCookie, getCookie, setCookie } from "hono/cookie"
import { Hono } from "hono/tiny"
import type { StatusCode } from "hono/utils/http-status"
/**
 * The `issuer` create an Draft Auth server, a [Hono](https://hono.dev) app that's
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
 * Enhanced authorization state with OIDC parameters for better compliance.
 * @internal
 */
export interface AuthorizationState {
	redirect_uri: string
	response_type: string
	state?: string
	client_id: string
	audience?: string
	nonce?: string
	prompt?: string
	max_age?: number
	ui_locales?: string
	id_token_hint?: string
	login_hint?: string
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
const DEFAULT_OAUTH_STATE_TTL_SECONDS = 60 * 10

/**
 * OIDC-compliant session data following OpenID Connect Session Management specification.
 * @interface SsoSessionData
 * @description Enhanced SSO session data that follows OIDC standards for better interoperability and compliance with OpenID Connect Session Management.
 * @internal
 */
export interface SsoSessionData<T = string> {
	/** The unique identifier of the user (OIDC 'sub' claim). */
	userId: string
	/** The type of the subject (e.g., "user"). */
	subjectType: T
	/** User's email, stored for convenience and OIDC email scope. */
	email?: string
	/** User's full name for OIDC profile scope. */
	name?: string
	/** User's preferred username for OIDC profile scope. */
	preferred_username?: string
	/** User's profile picture URL for OIDC profile scope. */
	picture?: string
	/** Timestamp (seconds since epoch) when this SSO session was initiated - OIDC 'auth_time'. */
	auth_time: number
	/** Timestamp (seconds since epoch) when this SSO session expires - OIDC 'exp'. */
	exp: number
	/** Session ID for OIDC Session Management - OIDC 'sid'. */
	sid: string
	/** The resolved subject string for token invalidation */
	resolvedSubject: string
	/** Original properties from the authentication flow for proper refresh handling */
	originalProperties: Record<string, unknown>
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
	 * When OIDC is enabled, automatically includes standard OIDC scopes: 'openid', 'profile', 'email'.
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
	 *     refresh: 60 * 60 * 24 * 365,
	 *     oauthState: 60 * 10
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
		/**
		 * Time-to-live in seconds for OAuth state cookies (authorization flow cookies).
		 * @default 10 minutes
		 */
		oauthState?: number
	}
	/**
	 * Enhanced SSO configuration with OIDC compliance and improved session management.
	 *
	 * This configuration follows OpenID Connect Session Management and RP-Initiated Logout specifications
	 * for better interoperability with OIDC-compliant clients.
	 *
	 * @example Basic SSO setup
	 * ```ts
	 * {
	 *   sso: {
	 *     enabled: true,
	 *     postLogoutRedirectUri: "https://myapp.com/logged-out"
	 *   }
	 * }
	 * ```
	 *
	 * @example Advanced OIDC-compliant setup
	 * ```ts
	 * {
	 *   sso: {
	 *     enabled: true,
	 *     oidcCompliant: true,
	 *     postLogoutRedirectUris: [
	 *       "https://myapp.com/logged-out",
	 *       "https://admin.myapp.com/logout"
	 *     ],
	 *     claimsSupported: ["sub", "name", "email", "picture"],
	 *     getSsoUserProperties: async (userId, sessionData, req, clientID, scopes) => {
	 *       // Fetch fresh user data from database
	 *       const user = await getUserById(userId)
	 *       return {
	 *         id: user.id,
	 *         email: user.email,
	 *         name: user.name,
	 *         picture: user.avatar
	 *       }
	 *     }
	 *   }
	 * }
	 * ```
	 */
	sso?: {
		/**
		 * @property Globally enables or disables Single Sign-On functionality.
		 * When enabled, follows OIDC Session Management specification for better interoperability.
		 * @default false
		 */
		enabled?: boolean
		/**
		 * @property The name of the SSO session cookie.
		 * If not provided, will use "__Host-draftauth-sso" for HTTPS and "draftauth-sso" for HTTP.
		 *
		 * @example
		 * ```ts
		 * cookieName: "my-app-sso-session"
		 * ```
		 */
		cookieName?: string
		/**
		 * @property Default URL to redirect to after a central logout from the issuer.
		 * Client applications can override this by providing a validated `post_logout_redirect_uri`.
		 * This should be registered in `postLogoutRedirectUris`.
		 *
		 * @example
		 * ```ts
		 * postLogoutRedirectUri: "https://myapp.com/logged-out"
		 * ```
		 */
		postLogoutRedirectUri?: string
		/**
		 * @property OIDC-compliant list of allowed post-logout redirect URIs.
		 * Each URI should be a complete URL that clients can redirect to after logout.
		 * This follows the OIDC RP-Initiated Logout specification.
		 *
		 * @example
		 * ```ts
		 * postLogoutRedirectUris: [
		 *   "https://myapp.com/logged-out",
		 *   "https://admin.myapp.com/logout"
		 * ]
		 * ```
		 */
		postLogoutRedirectUris?: string[]
		/**
		 * @property Domain for the SSO cookie (for cross-subdomain SSO)
		 * @example ".myapp.com" for SSO between api.myapp.com and admin.myapp.com
		 */
		cookieDomain?: string
		/**
		 * @property Force secure cookies even if HTTPS detection fails
		 * Useful when behind proxies/load balancers that terminate SSL
		 * @default false
		 */
		forceSecure?: boolean
		/**
		 * @property Enable OIDC-compliant features including ID tokens, UserInfo endpoint, and discovery.
		 * When enabled, adds OIDC discovery endpoint, ID token generation, and UserInfo endpoint.
		 * @default true
		 */
		oidcCompliant?: boolean
		/**
		 * @property Supported OIDC claims for the claims_supported discovery field.
		 * These claims will be advertised in the OIDC discovery document and can be included in ID tokens.
		 *
		 * @default ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "name", "email", "preferred_username", "picture"]
		 * @example
		 * ```ts
		 * claimsSupported: ["sub", "name", "email", "picture", "roles", "permissions"]
		 * ```
		 */
		claimsSupported?: string[]
		/**
		 * @callback isSsoUserStillValid
		 * @description Optional callback to perform a live check if the user identified by the SSO session
		 * is still valid (e.g., not disabled, not locked) before proceeding with SSO for a new client application.
		 * This callback allows you to implement real-time user validation during SSO flows.
		 *
		 * @example
		 * ```ts
		 * isSsoUserStillValid: async (userId, ssoSessionData, req) => {
		 *   const user = await getUserById(userId)
		 *   return user && user.isActive && !user.isLocked
		 * }
		 * ```
		 *
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
		 * If not provided, properties from the original SSO session establishment might be used,
		 * or it could fall back to using the main `refresh` callback logic if available.
		 *
		 * This callback is useful for:
		 * - Fetching updated user data from database
		 * - Including client-specific claims
		 * - Adding role/permission data based on the requesting application
		 *
		 * @example
		 * ```ts
		 * getSsoUserProperties: async (userId, sessionData, req, clientID, scopes) => {
		 *   const user = await getUserById(userId)
		 *   const clientPermissions = await getClientPermissions(clientID, userId)
		 *
		 *   return {
		 *     id: user.id,
		 *     email: user.email,
		 *     name: user.name,
		 *     picture: user.avatar,
		 *     roles: clientPermissions.roles,
		 *     permissions: clientPermissions.permissions
		 *   }
		 * }
		 * ```
		 *
		 * @param {string} userId - The user ID from the SSO session.
		 * @param {SsoSessionData} ssoSessionData - The full data of the SSO session.
		 * @param {Request} req - The incoming Hono request to the /authorize endpoint.
		 * @param {string} clientID - The clientID of the application requesting authorization via SSO.
		 * @param {string[]} scopes - The requested scopes for this authorization.
		 * @returns {Promise<Record<string, unknown>>} The properties to be included in the new token for the client app.
		 */
		getSsoUserProperties?: (
			userId: string,
			ssoSessionData: SsoSessionData<SubjectPayload<Subjects>["type"]>,
			req: Request,
			clientID: string,
			scopes: string[]
		) => Promise<Record<string, unknown>>
		/**
		 * @callback getSsoIdentifiers
		 * @description Optional callback to extract user identifiers from properties for SSO session creation.
		 * If not provided, will fallback to convention-based extraction (properties.id and properties.email).
		 * This allows you to customize how the userId and email are extracted from the properties object
		 * when a user completes authentication and an SSO session needs to be created.
		 *
		 * This callback is particularly useful when:
		 * - Your user properties use different field names than the defaults
		 * - You have different property structures for different subject types
		 * - You need to extract additional OIDC profile claims for SSO
		 *
		 * @example Basic custom field mapping
		 * ```ts
		 * getSsoIdentifiers: (properties, subjectType) => ({
		 *   userId: properties.userGuid, // Custom field name
		 *   email: properties.emailAddress, // Custom field name
		 *   name: properties.fullName,
		 *   preferred_username: properties.username
		 * })
		 * ```
		 *
		 * @example Different extraction logic based on subject type
		 * ```ts
		 * getSsoIdentifiers: (properties, subjectType) => {
		 *   if (subjectType === "admin") {
		 *     return {
		 *       userId: properties.adminId,
		 *       email: properties.adminEmail,
		 *       name: properties.adminName
		 *     }
		 *   }
		 *   return {
		 *     userId: properties.id,
		 *     email: properties.email,
		 *     name: properties.name
		 *   }
		 * }
		 * ```
		 *
		 * @param {SubjectPayload<Subjects>["properties"]} properties - The properties object from ctx.subject()
		 * @param {SubjectPayload<Subjects>["type"]} subjectType - The subject type (e.g., "user", "admin")
		 * @returns {{ userId: string; email?: string; name?: string; preferred_username?: string; picture?: string }} Object with userId (required) and optional OIDC profile claims
		 */
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
 * Enhanced token generation response with OIDC ID token support.
 * @internal
 */
interface TokenGenerationResult {
	access: string
	expiresIn: number
	refresh: string
	id_token?: string
}

/**
 * Enhanced code storage payload with OIDC parameters.
 * @internal
 */
interface CodeStoragePayload {
	type: string
	properties: unknown
	clientID: string
	redirectURI: string
	subject: string
	scopes?: string[]
	nonce?: string
	sessionId?: string
	authTime?: number
	ttl: {
		access: number
		refresh: number
	}
	pkce?: AuthorizationState["pkce"]
}

/**
 * Enhanced refresh token storage payload with OIDC parameters.
 * @internal
 */
interface RefreshTokenStoragePayload {
	type: string
	properties: unknown
	clientID: string
	subject: string
	scopes?: string[]
	nonce?: string
	sessionId?: string
	authTime?: number
	ttl: {
		access: number
		refresh: number
	}
	nextToken: string
	timeUsed?: number
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
		((err: UnknownStateError) => {
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
	const ttlOauthState = input.ttl?.oauthState ?? DEFAULT_OAUTH_STATE_TTL_SECONDS
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
	const oidcCompliant = input.sso?.oidcCompliant !== false // Default to true when SSO is enabled
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
	const allSupportedScopes =
		ssoEnabled && oidcCompliant
			? [...standardOidcScopes, ...(input.scopes_supported ?? [])]
			: input.scopes_supported

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
			const customName = input.sso.cookieName

			if (customName.startsWith("__Host-") && input.sso?.cookieDomain) {
				console.warn(
					`Cookie name "${customName}" uses __Host- prefix but cookieDomain is set. __Host- cookies cannot have domain attributes. Using fallback name.`
				)
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

	const validateLogoutRedirectUri = (uri: string): boolean => {
		// Check OIDC-compliant post_logout_redirect_uris first
		if (postLogoutRedirectUris.length > 0) {
			return postLogoutRedirectUris.some((allowedUri) => {
				try {
					const allowed = new URL(allowedUri)
					const requested = new URL(uri)
					return allowed.href === requested.href
				} catch {
					return false
				}
			})
		}

		return false
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
			sameSite: "Lax",
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
			const now = Math.floor(Date.now() / 1000)

			for (const [key] of keys) {
				try {
					const session = await Storage.get<SsoSessionData>(storage, key)
					if (session && session.exp < now) {
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

	/**
	 * Generate OIDC-compliant ID token when openid scope is present
	 * @internal
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
			if (payload.properties.preferred_username)
				claims.preferred_username = payload.properties.preferred_username
			if (payload.properties.picture) claims.picture = payload.properties.picture
		}

		if (payload.scopes.includes("email")) {
			if (payload.properties.email) claims.email = payload.properties.email
			if (payload.properties.email_verified !== undefined)
				claims.email_verified = payload.properties.email_verified
		}

		return await new SignJWT(claims)
			.setProtectedHeader({
				alg: signingKeyData.alg,
				kid: signingKeyData.id,
				typ: "JWT"
			})
			.sign(signingKeyData.private)
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

						if (authorization.response_type === "token") {
							const location = new URL(authorization.redirect_uri)
							const scopes = parseScopes(authorization.scopes)
							const tokens = await generateTokens(ctx, {
								subject,
								type: type as string,
								properties,
								clientID: authorization.client_id,
								scopes,
								nonce: authorization.nonce,
								sessionId: crypto.randomUUID(),
								authTime: Math.floor(Date.now() / 1000),
								ttl: {
									access: subjectOpts?.ttl?.access ?? ttlAccess,
									refresh: subjectOpts?.ttl?.refresh ?? ttlRefresh
								}
							})

							const hashParams = new URLSearchParams({
								access_token: tokens.access,
								token_type: "Bearer",
								expires_in: tokens.expiresIn.toString(),
								...(tokens.refresh && { refresh_token: tokens.refresh }),
								...(tokens.id_token && { id_token: tokens.id_token }),
								...(authorization.state && { state: authorization.state })
							})

							location.hash = hashParams.toString()
							await auth.unset(ctx, "authorization")
							return ctx.redirect(location.toString(), 302)
						}
						if (authorization.response_type === "code") {
							const code = crypto.randomUUID()
							const codePayload: CodeStoragePayload = {
								type,
								properties,
								subject,
								redirectURI: authorization.redirect_uri,
								clientID: authorization.client_id,
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

							const location = new URL(authorization.redirect_uri)
							location.searchParams.set("code", code)
							if (authorization.state) {
								location.searchParams.set("state", authorization.state)
							}
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
			nonce?: string
			sessionId?: string
			authTime?: number
		},
		opts?: {
			generateRefreshToken?: boolean
		}
	): Promise<TokenGenerationResult> => {
		const refreshToken = value.nextToken ?? crypto.randomUUID()
		if (opts?.generateRefreshToken ?? true) {
			/**
			 * Generate and store the next refresh token after the one we are currently returning.
			 * Reserving these in advance avoids concurrency issues with multiple refreshes.
			 * Similar treatment should be given to other values that may have race conditions,
			 * for example if a jti claim was added to the access token.
			 */
			const { timeUsed, ...refreshValueWithoutTimeUsed } = value
			const refreshValue: RefreshTokenStoragePayload = {
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

		const tokens: TokenGenerationResult = {
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

		// Generate ID token if openid scope is present and OIDC is enabled
		if (ssoEnabled && oidcCompliant && value.scopes?.includes("openid")) {
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

	// OIDC Discovery endpoint
	if (ssoEnabled && oidcCompliant) {
		app.get(
			"/.well-known/openid-configuration",
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
					userinfo_endpoint: `${iss}/userinfo`,
					jwks_uri: `${iss}/.well-known/jwks.json`,
					end_session_endpoint: `${iss}/logout`,
					revocation_endpoint: `${iss}/revoke`,
					response_types_supported: [
						"code",
						"token",
						"id_token",
						"code id_token",
						"code token",
						"id_token token",
						"code id_token token"
					],
					response_modes_supported: ["query", "fragment"],
					grant_types_supported: ["authorization_code", "refresh_token"],
					subject_types_supported: ["public"],
					id_token_signing_alg_values_supported: ["RS256"],
					scopes_supported: allSupportedScopes,
					claims_supported: claimsSupported,
					token_endpoint_auth_methods_supported: ["none"],
					claims_parameter_supported: false,
					request_parameter_supported: false,
					request_uri_parameter_supported: false,
					require_request_uri_registration: false
				})
			}
		)
	}

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
				scopes_supported: allSupportedScopes,
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

				const finalScopes = validateScopes(scope, payload.scopes)
				const tokens = await generateTokens(c, {
					...payload,
					scopes: finalScopes
				})
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

				const finalScopes = validateScopes(scope, payload.scopes)
				const tokens = await generateTokens(
					c,
					{
						...payload,
						scopes: finalScopes
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
		const nonce = c.req.query("nonce")
		const prompt = c.req.query("prompt")
		const max_age = c.req.query("max_age")
		const ui_locales = c.req.query("ui_locales")
		const id_token_hint = c.req.query("id_token_hint")
		const login_hint = c.req.query("login_hint")

		// Enhanced authorization state with OIDC parameters
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
			ui_locales,
			id_token_hint,
			login_hint,
			scopes: parseScopes(scope), // Legacy support
			pkce:
				code_challenge && code_challenge_method
					? {
							challenge: code_challenge,
							method: code_challenge_method as "S256"
						}
					: undefined
		} as AuthorizationState
		c.set("authorization", authorization)

		// OIDC validation: nonce required for implicit flow with id_token
		if (
			ssoEnabled &&
			oidcCompliant &&
			scope?.includes("openid") &&
			response_type?.includes("id_token") &&
			!nonce
		) {
			throw new OauthError(
				"invalid_request",
				"nonce is required for implicit flow with id_token"
			)
		}

		if (ssoEnabled) {
			const ssoCookieName = getSsoCookieName(c)
			const ssoSessionIdFromCookie = getCookie(c, ssoCookieName)
			if (ssoSessionIdFromCookie) {
				const ssoResult = await acquireSsoLock(ssoSessionIdFromCookie, async () => {
					const ssoSessionKey = ["sso:session", ssoSessionIdFromCookie]
					let ssoSessionData = await Storage.get<
						SsoSessionData<SubjectPayload<Subjects>["type"]>
					>(storage, ssoSessionKey)

					// Check session validity (both structure and expiration)
					const now = Math.floor(Date.now() / 1000)
					let isSsoSessionStructurallyValid =
						ssoSessionData?.userId && ssoSessionData.exp > now

					// Custom validation callback
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

					// Handle OIDC prompt parameter
					if (prompt === "none" && !isSsoSessionStructurallyValid) {
						// No valid session and prompt=none requires login_required error
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
						isSsoSessionStructurallyValid = false
					}

					// Check max_age if specified
					if (isSsoSessionStructurallyValid && ssoSessionData && max_age) {
						const maxAgeSeconds = Number.parseInt(max_age)
						if (now - ssoSessionData.auth_time > maxAgeSeconds) {
							await Storage.remove(storage, ssoSessionKey)
							deleteSsoCookie(c)
							ssoSessionData = null
							isSsoSessionStructurallyValid = false
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
							if (prompt === "none") {
								const errorUrl = new URL(redirect_uri)
								errorUrl.searchParams.set("error", "unauthorized_client")
								if (state) errorUrl.searchParams.set("state", state)
								return c.redirect(errorUrl.toString(), 302)
							}
							throw new UnauthorizedClientError(client_id, redirect_uri)
						}

						const authorizationForThisApp: AuthorizationState = {
							client_id,
							redirect_uri,
							response_type,
							state: state as string,
							nonce,
							prompt,
							max_age: authorization.max_age,
							ui_locales,
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

						let finalSubjectProperties: Record<string, unknown> =
							ssoSessionData.originalProperties
						let finalScopes = parseScopes(scope)

						// Get fresh user properties if callback provided
						if (input.sso?.getSsoUserProperties) {
							try {
								finalSubjectProperties = await input.sso.getSsoUserProperties(
									ssoSessionData.userId,
									ssoSessionData,
									c.req.raw,
									client_id,
									finalScopes || []
								)
							} catch (error) {
								console.error("Error getting SSO user properties:", error)
								finalSubjectProperties = ssoSessionData.originalProperties
							}
						} else if (input.refresh) {
							try {
								const refreshedClaims = await input.refresh(
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
							} catch (error) {
								console.error("Error refreshing SSO claims:", error)
								finalSubjectProperties = ssoSessionData.originalProperties
							}
						}

						const resolvedSsoUserJwtSubject =
							ssoSessionData.resolvedSubject ||
							(await resolveSubject(ssoSessionData.subjectType, finalSubjectProperties))

						if (authorizationForThisApp.response_type === "code") {
							const code = crypto.randomUUID()
							const codePayload: CodeStoragePayload = {
								type: ssoSessionData.subjectType,
								properties: finalSubjectProperties,
								subject: resolvedSsoUserJwtSubject,
								redirectURI: authorizationForThisApp.redirect_uri,
								clientID: authorizationForThisApp.client_id,
								pkce: authorizationForThisApp.pkce,
								scopes: finalScopes,
								nonce: authorizationForThisApp.nonce,
								sessionId: ssoSessionData.sid,
								authTime: ssoSessionData.auth_time,
								ttl: { access: ttlAccess, refresh: ttlRefresh }
							}

							await Storage.set(storage, ["oauth:code", code], codePayload, 60)

							const location = new URL(authorizationForThisApp.redirect_uri)
							location.searchParams.set("code", code)
							if (authorizationForThisApp.state)
								location.searchParams.set("state", authorizationForThisApp.state)
							await auth.unset(c, "authorization")
							setSsoCookie(c, ssoSessionIdFromCookie)
							return c.redirect(location.toString(), 302)
						}

						// Handle other response types for SSO
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

							const location = new URL(authorizationForThisApp.redirect_uri)
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
		await auth.set(c, "authorization", ttlOauthState, authorization)
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

	// Enhanced logout endpoint with OIDC RP-Initiated Logout support
	if (ssoEnabled) {
		app.get("/logout", async (c) => {
			const idTokenHint = c.req.query("id_token_hint")
			const postLogoutRedirectUri = c.req.query("post_logout_redirect_uri")
			const state = c.req.query("state")

			let sessionSub: string | undefined

			// Verify ID token hint if provided (OIDC RP-Initiated Logout)
			if (idTokenHint) {
				try {
					const signingKeyData = await signingKey()
					if (signingKeyData) {
						const result = await jwtVerify(idTokenHint, signingKeyData.public, {
							issuer: issuer(c)
						})
						sessionSub = result.payload.sub as string
					}
				} catch (error) {
					console.error("Invalid ID token hint:", error)
				}
			}

			const ssoCookieName = getSsoCookieName(c)
			const ssoSessionId = getCookie(c, ssoCookieName)
			if (ssoSessionId) {
				const ssoSessionKey = ["sso:session", ssoSessionId]
				const ssoSessionData = await Storage.get<SsoSessionData>(storage, ssoSessionKey)
				if (ssoSessionData) {
					// Invalidate all refresh tokens for this user
					await auth.invalidate(ssoSessionData.resolvedSubject)
				}
				await Storage.remove(storage, ssoSessionKey)
			}
			deleteSsoCookie(c)

			// Handle post_logout_redirect_uri with state parameter
			let redirectTo = postLogoutRedirectUri
			if (redirectTo && validateLogoutRedirectUri(redirectTo)) {
				const redirectUrl = new URL(redirectTo)
				if (state) {
					redirectUrl.searchParams.set("state", state)
				}
				return c.redirect(redirectUrl.toString(), 302)
			}

			redirectTo = input.sso?.postLogoutRedirectUri
			if (redirectTo) {
				const redirectUrl = new URL(redirectTo)
				if (state) {
					redirectUrl.searchParams.set("state", state)
				}
				return c.redirect(redirectUrl.toString(), 302)
			}

			return c.html(`
				<!DOCTYPE html>
				<html>
				<head>
					<title>Logout Successful</title>
					<meta charset="utf-8">
					<meta name="viewport" content="width=device-width, initial-scale=1">
				</head>
				<body>
					<h1>Logout Successful</h1>
					<p>You have been successfully logged out from Draft Auth.</p>
					${state ? `<p>State: ${state}</p>` : ""}
				</body>
				</html>
			`)
		})
	}

	// OIDC UserInfo endpoint
	if (ssoEnabled && oidcCompliant) {
		app.get(
			"/userinfo",
			cors({
				origin: "*",
				allowHeaders: ["*"],
				allowMethods: ["GET"],
				credentials: false
			}),
			async (c) => {
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
						return c.json(
							{
								error: "invalid_token",
								error_description: "Signing key not available"
							},
							401
						)
					}

					const result = await jwtVerify<{
						mode: "access"
						type: string
						properties: Record<string, unknown>
						scopes?: string[]
					}>(token, signingKeyData.public, {
						issuer: issuer(c)
					})

					if (result.payload.mode !== "access") {
						return c.json(
							{
								error: "invalid_token",
								error_description: "Invalid token type"
							},
							401
						)
					}

					// Check if openid scope is present
					if (!result.payload.scopes?.includes("openid")) {
						return c.json(
							{
								error: "insufficient_scope",
								error_description: "Token does not have openid scope"
							},
							403
						)
					}

					const userinfo: Record<string, unknown> = {
						sub: result.payload.sub
					}

					const props = result.payload.properties
					const scopes = result.payload.scopes || []

					// Add claims based on scopes
					if (scopes.includes("profile")) {
						if (props.name) userinfo.name = props.name
						if (props.preferred_username)
							userinfo.preferred_username = props.preferred_username
						if (props.picture) userinfo.picture = props.picture
					}

					if (scopes.includes("email")) {
						if (props.email) userinfo.email = props.email
						if (props.email_verified !== undefined)
							userinfo.email_verified = props.email_verified
					}

					return c.json(userinfo)
				} catch (error) {
					return c.json(
						{
							error: "invalid_token",
							error_description: "Token verification failed"
						},
						401
					)
				}
			}
		)
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
				const payload = await Storage.get<RefreshTokenStoragePayload>(storage, key)

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
						// Revoke all refresh tokens for this subject
						const keys = await Array.fromAsync(
							Storage.scan(storage, ["oauth:refresh", subject])
						)
						await Promise.all(keys.map(([scanKey]) => Storage.remove(storage, scanKey)))

						// Also remove SSO sessions for this subject
						if (ssoEnabled) {
							const sessionKeys = await Array.fromAsync(Storage.scan(storage, ["sso:session"]))
							for (const [sessionKey] of sessionKeys) {
								const sessionData = await Storage.get<SsoSessionData>(storage, sessionKey)
								if (sessionData && sessionData.resolvedSubject === subject) {
									await Storage.remove(storage, sessionKey)
								}
							}
						}
					}

					if (clientIDParam && !revokeAll) {
						const keys = await Array.fromAsync(
							Storage.scan(storage, ["oauth:refresh", subject])
						)

						for (const [scanKey] of keys) {
							const scanPayload = await Storage.get<RefreshTokenStoragePayload>(
								storage,
								scanKey
							)

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

	// Keep the original userinfo endpoint for backward compatibility when OIDC is not enabled
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

		try {
			const authorization = await getAuthorization(c)
			const url = new URL(authorization.redirect_uri)
			const oauth =
				err instanceof OauthError ? err : new OauthError("server_error", err.message)
			url.searchParams.set("error", oauth.error)
			url.searchParams.set("error_description", oauth.description)
			if (authorization.state) {
				url.searchParams.set("state", authorization.state)
			}
			return c.redirect(url.toString())
		} catch {
			// If we can't get authorization state, return JSON error
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
