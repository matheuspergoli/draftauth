/**
 * OpenID Connect (OIDC) authentication provider for Draft Auth.
 * Implements the OIDC Implicit Flow for client-side web applications.
 *
 * ## Quick Setup
 *
 * ```ts
 * import { OidcProvider } from "@draftauth/core/provider/oidc"
 *
 * export default issuer({
 *   providers: {
 *     auth0: OidcProvider({
 *       clientID: "your-client-id",
 *       issuer: "https://your-domain.auth0.com",
 *       scopes: ["openid", "profile", "email"]
 *     }),
 *     okta: OidcProvider({
 *       clientID: "okta-client-id",
 *       issuer: "https://your-domain.okta.com/oauth2/default"
 *     })
 *   }
 * })
 * ```
 *
 * ## Features
 *
 * - **OIDC Discovery**: Automatic endpoint discovery via well-known configuration
 * - **ID Token verification**: Secure JWT validation with issuer's public keys
 * - **Nonce validation**: CSRF protection through nonce verification
 * - **Flexible scopes**: Configurable OIDC scopes beyond the required 'openid'
 * - **Custom parameters**: Support for provider-specific authorization parameters
 *
 * ## User Data
 *
 * The provider returns the verified ID token claims and client information:
 *
 * ```ts
 * success: async (ctx, value) => {
 *   if (value.provider === "oidc") {
 *     console.log(value.id.sub)    // Subject (user ID)
 *     console.log(value.id.email)  // Email (if email scope requested)
 *     console.log(value.id.name)   // Name (if profile scope requested)
 *     console.log(value.clientID)  // Client ID used for this authentication
 *   }
 * }
 * ```
 *
 * @packageDocumentation
 */

import type { JWTPayload } from "hono/utils/jwt/types"
import { type JSONWebKeySet, createLocalJWKSet, jwtVerify } from "jose"
import type { WellKnown } from "../client"
import { OauthError, type OauthErrorType } from "../error"
import { getRelativeUrl, lazy } from "../util"
import type { Provider } from "./provider"

/**
 * Configuration options for the OIDC provider.
 */
export interface OidcConfig {
	/**
	 * Provider type identifier for internal use.
	 * @internal
	 * @default "oidc"
	 */
	readonly type?: string

	/**
	 * The client ID registered with the OIDC provider.
	 * This identifier is used in the authorization request and token validation.
	 *
	 * @example
	 * ```ts
	 * {
	 *   clientID: "my-web-app-12345"
	 * }
	 * ```
	 */
	readonly clientID: string

	/**
	 * The base URL of the OIDC authorization server.
	 * Used for OIDC discovery to find authorization and token endpoints.
	 *
	 * @example
	 * ```ts
	 * {
	 *   issuer: "https://accounts.google.com"
	 * }
	 * ```
	 */
	readonly issuer: string

	/**
	 * Additional OIDC scopes to request beyond the required 'openid' scope.
	 * Common scopes include 'profile', 'email', and provider-specific scopes.
	 *
	 * @default []
	 *
	 * @example
	 * ```ts
	 * {
	 *   scopes: ["profile", "email", "offline_access"]
	 * }
	 * ```
	 */
	readonly scopes?: string[]

	/**
	 * Additional query parameters to include in the authorization request.
	 * Useful for provider-specific parameters or customizing the auth flow.
	 *
	 * @example
	 * ```ts
	 * {
	 *   query: {
	 *     prompt: "consent",           // Force consent screen
	 *     max_age: "3600",            // Max session age
	 *     ui_locales: "en-US fr-CA"   // Preferred UI languages
	 *   }
	 * }
	 * ```
	 */
	readonly query?: Record<string, string>
}

/**
 * OIDC configuration without issuer-specific fields.
 * Used internally for provider wrapping.
 * @internal
 */
export type OidcWrappedConfig = Omit<OidcConfig, "issuer" | "name">

/**
 * Internal state maintained during the OIDC authentication flow.
 * Stored temporarily to validate the callback response.
 */
interface ProviderState {
	/** Random state parameter for CSRF protection */
	readonly state: string
	/** Random nonce for replay attack prevention */
	readonly nonce: string
	/** Callback URL for this authentication attempt */
	readonly redirect: string
}

/**
 * Structured ID token response with claims and raw data.
 * Used internally for processing OIDC responses.
 * @internal
 */
export interface IdTokenResponse {
	/** The raw ID token JWT string */
	readonly idToken: string
	/** Parsed and verified JWT claims */
	readonly claims: Record<string, unknown>
	/** Raw response data from the provider */
	readonly raw: Record<string, unknown>
}

/**
 * User data returned by successful OIDC authentication.
 */
export interface OidcUserData {
	/** Verified ID token claims containing user information */
	readonly id: JWTPayload
	/** Client ID used for this authentication */
	readonly clientID: string
}

/**
 * Creates an OpenID Connect authentication provider.
 * Implements the OIDC Implicit Flow with form_post response mode for security.
 *
 * @param config - OIDC provider configuration
 * @returns Provider instance implementing OIDC authentication
 *
 * @example
 * ```ts
 * // Auth0 provider
 * const auth0Provider = OidcProvider({
 *   clientID: process.env.AUTH0_CLIENT_ID,
 *   issuer: `https://${process.env.AUTH0_DOMAIN}`,
 *   scopes: ["openid", "profile", "email"],
 *   query: {
 *     audience: "https://myapi.com" // Auth0-specific
 *   }
 * })
 *
 * // Google provider
 * const googleProvider = OidcProvider({
 *   clientID: process.env.GOOGLE_CLIENT_ID,
 *   issuer: "https://accounts.google.com",
 *   scopes: ["profile", "email"],
 *   query: {
 *     hd: "mycompany.com" // Restrict to organization domain
 *   }
 * })
 * ```
 */
export const OidcProvider = (config: OidcConfig): Provider<OidcUserData> => {
	const authQuery = config.query || {}
	const additionalScopes = config.scopes || []

	/**
	 * Lazy-loaded OIDC discovery document.
	 * Fetches and caches the well-known configuration.
	 */
	const getWellKnown = lazy(() =>
		fetch(`${config.issuer}/.well-known/openid-configuration`).then(async (response) => {
			if (!response.ok) {
				throw new Error(`OIDC discovery failed: ${await response.text()}`)
			}
			return response.json() as Promise<WellKnown>
		})
	)

	/**
	 * Lazy-loaded JWKS for token verification.
	 * Fetches and caches the JSON Web Key Set.
	 */
	const getJWKS = lazy(() =>
		getWellKnown()
			.then((wellKnown) => wellKnown.jwks_uri)
			.then(async (jwksUri) => {
				const response = await fetch(jwksUri)
				if (!response.ok) {
					throw new Error(`JWKS fetch failed: ${await response.text()}`)
				}
				const keySet = (await response.json()) as JSONWebKeySet
				return createLocalJWKSet(keySet)
			})
	)

	return {
		type: config.type || "oidc",

		init(routes, ctx) {
			/**
			 * Initiates OIDC authentication flow.
			 * Redirects user to the provider's authorization endpoint with proper parameters.
			 */
			routes.get("/authorize", async (c) => {
				const provider: ProviderState = {
					state: crypto.randomUUID(),
					nonce: crypto.randomUUID(),
					redirect: getRelativeUrl(c, "./callback")
				}

				await ctx.set(c, "provider", 60 * 10, provider)

				const wellKnown = await getWellKnown()
				const authorizationUrl = new URL(wellKnown.authorization_endpoint)

				// Set required OIDC parameters
				authorizationUrl.searchParams.set("client_id", config.clientID)
				authorizationUrl.searchParams.set("response_type", "id_token")
				authorizationUrl.searchParams.set("response_mode", "form_post")
				authorizationUrl.searchParams.set("state", provider.state)
				authorizationUrl.searchParams.set("nonce", provider.nonce)
				authorizationUrl.searchParams.set("redirect_uri", provider.redirect)
				authorizationUrl.searchParams.set("scope", ["openid", ...additionalScopes].join(" "))

				// Add custom query parameters
				for (const [key, value] of Object.entries(authQuery)) {
					authorizationUrl.searchParams.set(key, value)
				}

				return c.redirect(authorizationUrl.toString())
			})

			/**
			 * Handles OIDC callback with form_post response.
			 * Validates the ID token and extracts user claims.
			 */
			routes.post("/callback", async (c) => {
				const provider = await ctx.get<ProviderState>(c, "provider")
				if (!provider) {
					return c.redirect(getRelativeUrl(c, "./authorize"))
				}

				const formData = await c.req.formData()

				// Check for OAuth errors
				const error = formData.get("error")
				if (error) {
					throw new OauthError(
						error.toString() as OauthErrorType,
						formData.get("error_description")?.toString() || ""
					)
				}

				// Extract and validate ID token
				const idToken = formData.get("id_token")
				if (!idToken) {
					throw new OauthError("invalid_request", "Missing id_token in callback")
				}

				try {
					const jwks = await getJWKS()
					const verificationResult = await jwtVerify(idToken.toString(), jwks, {
						audience: config.clientID,
						issuer: config.issuer
					})

					// Validate nonce to prevent replay attacks
					if (verificationResult.payload.nonce !== provider.nonce) {
						throw new OauthError("invalid_request", "Nonce validation failed")
					}

					return ctx.success(c, {
						id: verificationResult.payload,
						clientID: config.clientID
					})
				} catch (error) {
					if (error instanceof OauthError) {
						throw error
					}
					throw new OauthError(
						"invalid_request",
						`ID token verification failed: ${error instanceof Error ? error.message : "Unknown error"}`
					)
				}
			})
		}
	}
}
