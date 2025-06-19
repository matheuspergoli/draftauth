/**
 * OAuth 2.0 authentication provider for Draft Auth.
 * Implements the Authorization Code Grant flow with optional PKCE support.
 *
 * ## Quick Setup
 *
 * ```ts
 * import { Oauth2Provider } from "@draftauth/core/provider/oauth2"
 *
 * export default issuer({
 *   providers: {
 *     github: Oauth2Provider({
 *       clientID: process.env.GITHUB_CLIENT_ID,
 *       clientSecret: process.env.GITHUB_CLIENT_SECRET,
 *       endpoint: {
 *         authorization: "https://github.com/login/oauth/authorize",
 *         token: "https://github.com/login/oauth/access_token"
 *       },
 *       scopes: ["user:email", "read:user"]
 *     }),
 *     discord: Oauth2Provider({
 *       clientID: process.env.DISCORD_CLIENT_ID,
 *       clientSecret: process.env.DISCORD_CLIENT_SECRET,
 *       endpoint: {
 *         authorization: "https://discord.com/api/oauth2/authorize",
 *         token: "https://discord.com/api/oauth2/token"
 *       },
 *       scopes: ["identify", "email"],
 *       pkce: true // Required by some providers
 *     })
 *   }
 * })
 * ```
 *
 * ## Features
 *
 * - **Authorization Code Grant**: Secure server-side OAuth 2.0 flow
 * - **PKCE Support**: Optional Proof Key for Code Exchange for enhanced security
 * - **ID Token Support**: Optional JWT verification for OpenID Connect compatibility
 * - **Flexible Endpoints**: Configure custom authorization and token endpoints
 * - **Custom Parameters**: Support for provider-specific authorization parameters
 *
 * ## User Data
 *
 * The provider returns access tokens and optional ID token claims:
 *
 * ```ts
 * success: async (ctx, value) => {
 *   if (value.provider === "oauth2") {
 *     // Access token for API calls: value.tokenset.access
 *     // Refresh token (if provided): value.tokenset.refresh
 *     // ID token claims (if JWT endpoint configured): value.tokenset.id
 *     // Client ID used: value.clientID
 *   }
 * }
 * ```
 *
 * @packageDocumentation
 */

import type { Context } from "hono"
import { createRemoteJWKSet, jwtVerify } from "jose"
import { OauthError, type OauthErrorType } from "../error"
import { generatePKCE } from "../pkce"
import { getRelativeUrl } from "../util"
import type { Provider } from "./provider"

/**
 * Configuration options for the OAuth 2.0 provider.
 */
export interface Oauth2Config {
	/**
	 * Provider type identifier for internal use.
	 * @internal
	 * @default "oauth2"
	 */
	readonly type?: string

	/**
	 * The client ID registered with the OAuth 2.0 provider.
	 * This public identifier is used in authorization requests.
	 *
	 * @example
	 * ```ts
	 * {
	 *   clientID: "github-app-12345"
	 * }
	 * ```
	 */
	readonly clientID: string

	/**
	 * The client secret for authenticating with the OAuth 2.0 provider.
	 * This private credential must be kept secure and not exposed to clients.
	 *
	 * @example
	 * ```ts
	 * {
	 *   clientSecret: process.env.OAUTH_CLIENT_SECRET
	 * }
	 * ```
	 */
	readonly clientSecret: string

	/**
	 * OAuth 2.0 endpoint URLs for the authorization and token flows.
	 */
	readonly endpoint: {
		/**
		 * The authorization endpoint where users are redirected for authentication.
		 *
		 * @example "https://github.com/login/oauth/authorize"
		 */
		readonly authorization: string

		/**
		 * The token endpoint for exchanging authorization codes for access tokens.
		 *
		 * @example "https://github.com/login/oauth/access_token"
		 */
		readonly token: string

		/**
		 * Optional JWKS endpoint for verifying ID tokens.
		 * Required only if the provider returns ID tokens that need verification.
		 *
		 * @example "https://provider.com/.well-known/jwks.json"
		 */
		readonly jwks?: string
	}

	/**
	 * OAuth 2.0 scopes to request during authorization.
	 * Scopes define the level of access being requested.
	 *
	 * @example
	 * ```ts
	 * {
	 *   scopes: ["user:email", "read:user", "repo"]
	 * }
	 * ```
	 */
	readonly scopes: string[]

	/**
	 * Whether to use PKCE (Proof Key for Code Exchange) for enhanced security.
	 * Recommended for public clients and required by some providers.
	 *
	 * @default false
	 *
	 * @example
	 * ```ts
	 * {
	 *   pkce: true // Required for Twitter/X, recommended for mobile apps
	 * }
	 * ```
	 */
	readonly pkce?: boolean

	/**
	 * Additional query parameters to include in the authorization request.
	 * Useful for provider-specific parameters or customizing the auth flow.
	 *
	 * @example
	 * ```ts
	 * {
	 *   query: {
	 *     access_type: "offline",    // Request refresh token
	 *     prompt: "consent",         // Force consent screen
	 *     hd: "mycompany.com"       // Google Workspace domain
	 *   }
	 * }
	 * ```
	 */
	readonly query?: Record<string, string>
}

/**
 * OAuth 2.0 configuration without endpoint-specific fields.
 * Used internally for provider wrapping.
 * @internal
 */
export type Oauth2WrappedConfig = Omit<Oauth2Config, "endpoint" | "name">

/**
 * OAuth 2.0 token response containing access tokens and metadata.
 * Provides a structured interface for token data with lazy property access.
 * @internal
 */
export interface Oauth2Token {
	/** Access token for making authenticated API requests */
	readonly access: string
	/** Refresh token for obtaining new access tokens (if provided) */
	readonly refresh: string
	/** Token expiration time in seconds (if provided) */
	readonly expiry: number
	/** Verified ID token claims (if JWKS endpoint configured) */
	readonly id: Record<string, unknown> | null
	/** Raw token response from the provider */
	readonly raw: Record<string, unknown>
}

/**
 * Internal state maintained during the OAuth 2.0 authentication flow.
 * Stored temporarily to validate the callback response.
 */
interface ProviderState {
	/** Random state parameter for CSRF protection */
	readonly state: string
	/** Callback URL for this authentication attempt */
	readonly redirect: string
	/** PKCE code verifier (if PKCE is enabled) */
	readonly codeVerifier?: string
}

/**
 * OAuth 2.0 token endpoint response structure.
 * Follows the standard OAuth 2.0 token response format.
 */
interface TokenResponse {
	/** Access token issued by the authorization server */
	readonly access_token: string
	/** Optional refresh token for obtaining new access tokens */
	readonly refresh_token?: string
	/** Lifetime in seconds of the access token */
	readonly expires_in?: number
	/** Optional ID token for OpenID Connect compatibility */
	readonly id_token?: string
	/** Error code if the request failed */
	readonly error?: string
	/** Human-readable error description */
	readonly error_description?: string
	/** Additional provider-specific fields */
	readonly [key: string]: unknown
}

/**
 * User data returned by successful OAuth 2.0 authentication.
 */
export interface Oauth2UserData {
	/** Token set containing access token, refresh token, and metadata */
	readonly tokenset: Oauth2Token
	/** Client ID used for this authentication */
	readonly clientID: string
}

/**
 * Creates an OAuth 2.0 authentication provider.
 * Implements the Authorization Code Grant flow with optional PKCE support.
 *
 * @param config - OAuth 2.0 provider configuration
 * @returns Provider instance implementing OAuth 2.0 authentication
 *
 * @example
 * ```ts
 * // GitHub provider with basic configuration
 * const githubProvider = Oauth2Provider({
 *   clientID: process.env.GITHUB_CLIENT_ID,
 *   clientSecret: process.env.GITHUB_CLIENT_SECRET,
 *   endpoint: {
 *     authorization: "https://github.com/login/oauth/authorize",
 *     token: "https://github.com/login/oauth/access_token"
 *   },
 *   scopes: ["user:email", "read:user"]
 * })
 *
 * // Provider with PKCE and custom parameters
 * const customProvider = Oauth2Provider({
 *   clientID: "my-client-id",
 *   clientSecret: "my-client-secret",
 *   endpoint: {
 *     authorization: "https://provider.com/oauth/authorize",
 *     token: "https://provider.com/oauth/token",
 *     jwks: "https://provider.com/.well-known/jwks.json"
 *   },
 *   scopes: ["openid", "profile", "email"],
 *   pkce: true,
 *   query: {
 *     prompt: "consent",
 *     access_type: "offline"
 *   }
 * })
 * ```
 */
export const Oauth2Provider = (config: Oauth2Config): Provider<Oauth2UserData> => {
	const authQuery = config.query || {}

	/**
	 * Handles the OAuth 2.0 callback logic for both GET and POST requests.
	 * Exchanges the authorization code for tokens and processes the response.
	 */
	const handleCallbackLogic = async (
		c: Context,
		ctx: {
			get: <T>(c: Context, key: string) => Promise<T | undefined>
			set: <T>(c: Context, key: string, ttl: number, value: T) => Promise<void>
			success: (c: Context, data: Oauth2UserData) => Promise<Response>
		},
		provider: ProviderState,
		code: string | undefined
	): Promise<Response> => {
		if (!provider || !code) {
			return c.redirect(getRelativeUrl(c, "./authorize"))
		}

		// Prepare token exchange request
		const tokenRequestBody = new URLSearchParams({
			client_id: config.clientID,
			client_secret: config.clientSecret,
			code,
			grant_type: "authorization_code",
			redirect_uri: provider.redirect,
			...(provider.codeVerifier ? { code_verifier: provider.codeVerifier } : {})
		})

		try {
			// Exchange authorization code for tokens
			const response = await fetch(config.endpoint.token, {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded",
					Accept: "application/json"
				},
				body: tokenRequestBody.toString()
			})

			if (!response.ok) {
				throw new Error(`Token request failed with status ${response.status}`)
			}

			const tokenData = (await response.json()) as TokenResponse

			// Check for OAuth errors in response
			if (tokenData.error) {
				throw new OauthError(
					tokenData.error as OauthErrorType,
					tokenData.error_description || ""
				)
			}

			// Verify ID token if JWKS endpoint is configured
			let idTokenPayload: Record<string, unknown> | null = null
			if (config.endpoint.jwks && tokenData.id_token) {
				try {
					const jwksEndpoint = new URL(config.endpoint.jwks)
					const jwks = createRemoteJWKSet(jwksEndpoint)
					const verificationResult = await jwtVerify(tokenData.id_token, jwks, {
						audience: config.clientID
					})
					idTokenPayload = verificationResult.payload
				} catch {
					// Continue without ID token claims rather than failing the entire flow
				}
			}

			return await ctx.success(c, {
				clientID: config.clientID,
				tokenset: {
					get access(): string {
						return tokenData.access_token
					},
					get refresh(): string {
						return tokenData.refresh_token || ""
					},
					get expiry(): number {
						return tokenData.expires_in || 0
					},
					get id(): Record<string, unknown> | null {
						return idTokenPayload
					},
					get raw(): Record<string, unknown> {
						return tokenData
					}
				}
			})
		} catch (error) {
			if (error instanceof OauthError) {
				throw error
			}
			throw new OauthError(
				"server_error",
				`Token exchange failed: ${error instanceof Error ? error.message : "Unknown error"}`
			)
		}
	}

	return {
		type: config.type || "oauth2",

		init(routes, ctx) {
			/**
			 * Initiates OAuth 2.0 authorization flow.
			 * Redirects user to the provider's authorization endpoint with proper parameters.
			 */
			routes.get("/authorize", async (c: Context) => {
				const state = crypto.randomUUID()
				const pkce = config.pkce ? await generatePKCE() : undefined

				await ctx.set<ProviderState>(c, "provider", 60 * 10, {
					state,
					redirect: getRelativeUrl(c, "./callback"),
					codeVerifier: pkce?.verifier
				})

				const authorizationUrl = new URL(config.endpoint.authorization)

				// Set required OAuth 2.0 parameters
				authorizationUrl.searchParams.set("client_id", config.clientID)
				authorizationUrl.searchParams.set("redirect_uri", getRelativeUrl(c, "./callback"))
				authorizationUrl.searchParams.set("response_type", "code")
				authorizationUrl.searchParams.set("state", state)
				authorizationUrl.searchParams.set("scope", config.scopes.join(" "))

				// Add PKCE parameters if enabled
				if (pkce) {
					authorizationUrl.searchParams.set("code_challenge", pkce.challenge)
					authorizationUrl.searchParams.set("code_challenge_method", pkce.method)
				}

				// Add custom query parameters
				for (const [key, value] of Object.entries(authQuery)) {
					authorizationUrl.searchParams.set(key, value)
				}

				return c.redirect(authorizationUrl.toString())
			})

			/**
			 * Handles OAuth 2.0 callback via query parameters (GET request).
			 * Standard OAuth 2.0 callback method for most providers.
			 */
			routes.get("/callback", async (c: Context) => {
				const provider = (await ctx.get(c, "provider")) as ProviderState
				const code = c.req.query("code")
				const state = c.req.query("state")
				const error = c.req.query("error")

				// Check for OAuth errors
				if (error) {
					throw new OauthError(error as OauthErrorType, c.req.query("error_description") || "")
				}

				// Validate state and presence of required parameters
				if (!provider || !code || (provider.state && state !== provider.state)) {
					return c.redirect(getRelativeUrl(c, "./authorize"))
				}

				return await handleCallbackLogic(c, ctx, provider, code)
			})

			/**
			 * Handles OAuth 2.0 callback via form data (POST request).
			 * Alternative callback method supported by some providers.
			 */
			routes.post("/callback", async (c: Context) => {
				const provider = (await ctx.get(c, "provider")) as ProviderState
				const formData = await c.req.formData()

				const code = formData.get("code")?.toString()
				const state = formData.get("state")?.toString()
				const error = formData.get("error")?.toString()

				// Check for OAuth errors
				if (error) {
					throw new OauthError(
						error as OauthErrorType,
						formData.get("error_description")?.toString() || ""
					)
				}

				// Validate state and presence of required parameters
				if (!provider || !code || (provider.state && state !== provider.state)) {
					return c.redirect(getRelativeUrl(c, "./authorize"))
				}

				return await handleCallbackLogic(c, ctx, provider, code)
			})
		}
	}
}
