/**
 * Google authentication providers for Draft Auth.
 * Supports both OAuth 2.0 and OpenID Connect flows for Google Sign-In.
 *
 * ## OAuth 2.0 Provider
 *
 * Use OAuth 2.0 when you need access tokens for calling Google APIs:
 *
 * ```ts
 * import { GoogleProvider } from "@draftauth/core/provider/google"
 *
 * export default issuer({
 *   providers: {
 *     google: GoogleProvider({
 *       clientID: process.env.GOOGLE_CLIENT_ID,
 *       clientSecret: process.env.GOOGLE_CLIENT_SECRET,
 *       scopes: ["profile", "email", "https://www.googleapis.com/auth/calendar.readonly"]
 *     })
 *   }
 * })
 * ```
 *
 * ## OIDC Provider
 *
 * Use OIDC for simple authentication when you only need user identity:
 *
 * ```ts
 * import { GoogleOidcProvider } from "@draftauth/core/provider/google"
 *
 * export default issuer({
 *   providers: {
 *     google: GoogleOidcProvider({
 *       clientID: process.env.GOOGLE_CLIENT_ID,
 *       scopes: ["profile", "email"]
 *     })
 *   }
 * })
 * ```
 *
 * ## Configuration Options
 *
 * ### OAuth 2.0 Specific
 * - Access tokens for Google API calls
 * - Refresh tokens for long-lived access
 * - Support for offline access
 *
 * ### OIDC Specific
 * - ID tokens with verified user claims
 * - Simpler setup (no client secret needed)
 * - Perfect for authentication-only use cases
 *
 * ## User Data Access
 *
 * ```ts
 * success: async (ctx, value) => {
 *   if (value.provider === "google") {
 *     // OAuth 2.0 flow
 *     if (value.tokenset) {
 *       console.log(value.tokenset.access) // Use for API calls
 *       console.log(value.tokenset.id?.email) // User email from ID token
 *     }
 *
 *     // OIDC flow
 *     if (value.id) {
 *       console.log(value.id.sub)   // Google user ID
 *       console.log(value.id.email) // Verified email
 *       console.log(value.id.name)  // Full name
 *       console.log(value.id.picture) // Profile picture URL
 *     }
 *   }
 * }
 * ```
 *
 * @packageDocumentation
 */

import { Oauth2Provider, type Oauth2WrappedConfig } from "./oauth2"
import { OidcProvider, type OidcWrappedConfig } from "./oidc"

/**
 * Configuration options for Google OAuth 2.0 provider.
 * Extends the base OAuth 2.0 configuration with Google-specific defaults.
 */
export interface GoogleConfig extends Oauth2WrappedConfig {
	/**
	 * Google OAuth 2.0 client ID from Google Cloud Console.
	 *
	 * @example
	 * ```ts
	 * {
	 *   clientID: "123456789-abc123.apps.googleusercontent.com"
	 * }
	 * ```
	 */
	readonly clientID: string

	/**
	 * Google OAuth 2.0 client secret from Google Cloud Console.
	 * Required for server-side OAuth 2.0 flows.
	 *
	 * @example
	 * ```ts
	 * {
	 *   clientSecret: process.env.GOOGLE_CLIENT_SECRET
	 * }
	 * ```
	 */
	readonly clientSecret: string

	/**
	 * Google OAuth 2.0 scopes to request.
	 * Common scopes include 'profile', 'email', and specific Google API scopes.
	 *
	 * @example
	 * ```ts
	 * {
	 *   scopes: [
	 *     "profile",
	 *     "email",
	 *     "https://www.googleapis.com/auth/calendar.readonly",
	 *     "https://www.googleapis.com/auth/drive.file"
	 *   ]
	 * }
	 * ```
	 */
	readonly scopes: string[]

	/**
	 * Additional query parameters for Google OAuth 2.0.
	 * Useful for Google-specific options like hosted domain restrictions.
	 *
	 * @example
	 * ```ts
	 * {
	 *   query: {
	 *     hd: "mycompany.com",        // Restrict to Google Workspace domain
	 *     access_type: "offline",     // Request refresh token
	 *     prompt: "consent",          // Force consent screen
	 *     include_granted_scopes: "true" // Incremental authorization
	 *   }
	 * }
	 * ```
	 */
	readonly query?: Record<string, string>
}

/**
 * Configuration options for Google OIDC provider.
 * Extends the base OIDC configuration with Google-specific defaults.
 */
export interface GoogleOidcConfig extends OidcWrappedConfig {
	/**
	 * Google OAuth 2.0 client ID from Google Cloud Console.
	 * No client secret needed for OIDC flows.
	 *
	 * @example
	 * ```ts
	 * {
	 *   clientID: "123456789-abc123.apps.googleusercontent.com"
	 * }
	 * ```
	 */
	readonly clientID: string

	/**
	 * OIDC scopes to request from Google.
	 * The 'openid' scope is automatically included.
	 *
	 * @example
	 * ```ts
	 * {
	 *   scopes: ["profile", "email"]
	 * }
	 * ```
	 */
	readonly scopes: string[]

	/**
	 * Additional query parameters for Google OIDC.
	 *
	 * @example
	 * ```ts
	 * {
	 *   query: {
	 *     hd: "mycompany.com",    // Restrict to Google Workspace domain
	 *     prompt: "select_account" // Show account chooser
	 *   }
	 * }
	 * ```
	 */
	readonly query?: Record<string, string>
}

/**
 * Creates a Google OAuth 2.0 authentication provider.
 * Use this when you need access tokens to call Google APIs on behalf of the user.
 *
 * @param config - Google OAuth 2.0 configuration
 * @returns OAuth 2.0 provider configured for Google
 *
 * @example
 * ```ts
 * // Basic setup for user authentication
 * const basicGoogle = GoogleProvider({
 *   clientID: process.env.GOOGLE_CLIENT_ID,
 *   clientSecret: process.env.GOOGLE_CLIENT_SECRET
 * })
 *
 * // Advanced setup with API access
 * const advancedGoogle = GoogleProvider({
 *   clientID: process.env.GOOGLE_CLIENT_ID,
 *   clientSecret: process.env.GOOGLE_CLIENT_SECRET,
 *   scopes: [
 *     "profile",
 *     "email",
 *     "https://www.googleapis.com/auth/calendar.readonly",
 *     "https://www.googleapis.com/auth/drive.file"
 *   ],
 *   query: {
 *     access_type: "offline",    // Get refresh token
 *     prompt: "consent",         // Force consent for refresh token
 *     hd: "mycompany.com"       // Restrict to company domain
 *   }
 * })
 *
 * // Use the access token for API calls
 * success: async (ctx, value) => {
 *   const accessToken = value.tokenset.access
 *   const response = await fetch('https://www.googleapis.com/calendar/v3/calendars/primary/events', {
 *     headers: { Authorization: `Bearer ${accessToken}` }
 *   })
 * }
 * ```
 */
export const GoogleProvider = (config: GoogleConfig) => {
	return Oauth2Provider({
		...config,
		type: "google",
		endpoint: {
			authorization: "https://accounts.google.com/o/oauth2/v2/auth",
			token: "https://oauth2.googleapis.com/token",
			jwks: "https://www.googleapis.com/oauth2/v3/certs"
		}
	})
}

/**
 * Creates a Google OpenID Connect authentication provider.
 * Use this for simple user authentication when you only need user identity information.
 *
 * @param config - Google OIDC configuration
 * @returns OIDC provider configured for Google
 *
 * @example
 * ```ts
 * // Simple authentication setup
 * const simpleGoogle = GoogleOidcProvider({
 *   clientID: process.env.GOOGLE_CLIENT_ID
 * })
 *
 * // With Google Workspace domain restriction
 * const workspaceGoogle = GoogleOidcProvider({
 *   clientID: process.env.GOOGLE_CLIENT_ID,
 *   scopes: ["profile", "email"],
 *   query: {
 *     hd: "mycompany.com",        // Only allow company Google accounts
 *     prompt: "select_account"    // Always show account chooser
 *   }
 * })
 *
 * // Access user information from ID token
 * success: async (ctx, value) => {
 *   const user = value.id
 *   console.log(`User ${user.name} (${user.email}) authenticated`)
 *   console.log(`Google ID: ${user.sub}`)
 *   console.log(`Profile picture: ${user.picture}`)
 * }
 * ```
 */
export const GoogleOidcProvider = (config: GoogleOidcConfig) => {
	return OidcProvider({
		...config,
		type: "google",
		issuer: "https://accounts.google.com"
	})
}
