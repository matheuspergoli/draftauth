import type { Context, Hono } from "hono"
import type { StorageAdapter } from "../storage/storage"

/**
 * OAuth provider system for Draft Auth.
 * Defines the interfaces and utilities for implementing authentication providers
 * that integrate with various OAuth 2.0 and OpenID Connect services.
 *
 * ## Creating a Provider
 *
 * ```ts
 * export const MyProvider = (config: MyConfig): Provider<MyUserData> => ({
 *   type: "my-provider",
 *
 *   init(routes, ctx) {
 *     routes.get("/authorize", async (c) => {
 *       // Redirect to provider's auth URL
 *       return c.redirect(authUrl)
 *     })
 *
 *     routes.get("/callback", async (c) => {
 *       // Handle callback and extract user data
 *       const userData = await processCallback(c)
 *       return await ctx.success(c, userData)
 *     })
 *   }
 * })
 * ```
 *
 * ## Using Providers
 *
 * ```ts
 * export default issuer({
 *   providers: {
 *     github: GithubProvider({ ... }),
 *     google: GoogleProvider({ ... })
 *   }
 * })
 * ```
 */

/**
 * Hono router instance used for provider route definitions.
 * Providers use this to register their authorization and callback endpoints.
 */
export type ProviderRoute = Hono

/**
 * Authentication provider interface that handles OAuth flows.
 * Each provider implements authentication with a specific service (GitHub, Google, etc.).
 *
 * @template Properties - Type of user data returned by successful authentication
 */
export interface Provider<Properties = Record<string, unknown>> {
	/**
	 * Unique identifier for this provider type.
	 * Used in URLs and provider selection UI.
	 *
	 * @example "github", "google", "steam"
	 */
	readonly type: string

	/**
	 * Initializes the provider by registering required routes.
	 * Called during issuer setup to configure authorization and callback endpoints.
	 *
	 * @param route - Hono router for registering provider endpoints
	 * @param options - Provider utilities and configuration
	 *
	 * @example
	 * ```ts
	 * init(routes, ctx) {
	 *   routes.get("/authorize", async (c) => {
	 *     // Redirect to OAuth provider
	 *     return c.redirect(buildAuthUrl())
	 *   })
	 *
	 *   routes.get("/callback", async (c) => {
	 *     // Process callback and return user data
	 *     const userData = await handleCallback(c)
	 *     return await ctx.success(c, userData)
	 *   })
	 * }
	 * ```
	 */
	init: (route: ProviderRoute, options: ProviderOptions<Properties>) => void

	/**
	 * Optional client-side authentication method for server-to-server flows.
	 * Used when the provider supports direct client credential authentication.
	 *
	 * @param input - Client credentials and parameters
	 * @returns Promise resolving to user properties
	 *
	 * @example
	 * ```ts
	 * client: async ({ clientID, clientSecret, params }) => {
	 *   const response = await fetch('/oauth/token', {
	 *     headers: { Authorization: `Basic ${btoa(`${clientID}:${clientSecret}`)}` },
	 *     body: new URLSearchParams(params)
	 *   })
	 *   return await processTokenResponse(response)
	 * }
	 * ```
	 */
	readonly client?: (input: {
		readonly clientID: string
		readonly clientSecret: string
		readonly params: Record<string, string>
	}) => Promise<Properties>
}

/**
 * Utilities and callbacks provided to providers during initialization.
 * Contains methods for state management, user flow completion, and storage access.
 *
 * @template Properties - Type of user data handled by the provider
 */
export interface ProviderOptions<Properties> {
	/**
	 * Name of the provider instance as configured in the issuer.
	 * Corresponds to the key used in the providers object.
	 */
	readonly name: string

	/**
	 * Completes the authentication flow with user data.
	 * Called when the provider successfully authenticates a user.
	 *
	 * @param ctx - Hono request context
	 * @param properties - User data extracted from the provider
	 * @param opts - Optional utilities for session management
	 * @returns Response that completes the OAuth flow
	 *
	 * @example
	 * ```ts
	 * const userData = { userId: "123", email: "user@example.com" }
	 * return await ctx.success(c, userData)
	 * ```
	 */
	success: (
		ctx: Context,
		properties: Properties,
		opts?: {
			/** Function to invalidate existing user sessions */
			readonly invalidate?: (subject: string) => Promise<void>
		}
	) => Promise<Response>

	/**
	 * Forwards a response through the provider context.
	 * Used for redirects and custom responses within the OAuth flow.
	 *
	 * @param ctx - Hono request context
	 * @param response - Response to forward
	 * @returns Forwarded response
	 */
	forward: (ctx: Context, response: Response) => Response

	/**
	 * Stores a temporary value with expiration for the current session.
	 * Useful for storing OAuth state, PKCE verifiers, and other temporary data.
	 *
	 * @param ctx - Hono request context
	 * @param key - Storage key identifier
	 * @param maxAge - TTL in seconds
	 * @param value - Value to store
	 *
	 * @example
	 * ```ts
	 * // Store OAuth state for 10 minutes
	 * await ctx.set(c, "oauth_state", 600, { state, redirectUri })
	 * ```
	 */
	set: <T>(ctx: Context, key: string, maxAge: number, value: T) => Promise<void>

	/**
	 * Retrieves a previously stored temporary value.
	 *
	 * @param ctx - Hono request context
	 * @param key - Storage key identifier
	 * @returns Promise resolving to the stored value or undefined if not found/expired
	 *
	 * @example
	 * ```ts
	 * const oauthState = await ctx.get<OAuthState>(c, "oauth_state")
	 * if (!oauthState) {
	 *   throw new Error("OAuth state expired")
	 * }
	 * ```
	 */
	get: <T>(ctx: Context, key: string) => Promise<T | undefined>

	/**
	 * Removes a stored temporary value.
	 *
	 * @param ctx - Hono request context
	 * @param key - Storage key identifier
	 *
	 * @example
	 * ```ts
	 * // Clean up OAuth state after use
	 * await ctx.unset(c, "oauth_state")
	 * ```
	 */
	unset: (ctx: Context, key: string) => Promise<void>

	/**
	 * Invalidates all sessions for a given subject (user).
	 * Forces logout across all devices and applications.
	 *
	 * @param subject - Subject identifier to invalidate
	 *
	 * @example
	 * ```ts
	 * // Force logout on password change
	 * await ctx.invalidate(userId)
	 * ```
	 */
	invalidate: (subject: string) => Promise<void>

	/**
	 * Storage adapter for persistent data operations.
	 * Provides access to the configured storage backend.
	 */
	readonly storage: StorageAdapter
}

/**
 * Base error class for provider-related errors.
 * Extend this class to create specific provider error types.
 *
 * @example
 * ```ts
 * export class GitHubApiError extends ProviderError {
 *   constructor(message: string, public readonly statusCode: number) {
 *     super(message)
 *   }
 * }
 * ```
 */
export class ProviderError extends Error {
	constructor(message: string) {
		super(message)
		this.name = "ProviderError"
	}
}

/**
 * Error thrown when a provider encounters an unknown or unexpected error.
 * Used as a fallback for unhandled error conditions.
 *
 * @example
 * ```ts
 * catch (error) {
 *   if (error instanceof SomeSpecificError) {
 *     // Handle specific error
 *   } else {
 *     throw new ProviderUnknownError(`Unexpected error: ${error}`)
 *   }
 * }
 * ```
 */
export class ProviderUnknownError extends ProviderError {
	constructor(message?: string) {
		super(message || "An unknown provider error occurred")
		this.name = "ProviderUnknownError"
	}
}
