/**
 * Facebook authentication providers for Draft Auth.
 * Supports both OAuth 2.0 and OpenID Connect flows for Facebook Login.
 *
 * ## OAuth 2.0 Provider
 *
 * Use OAuth 2.0 when you need access tokens for calling Facebook Graph API:
 *
 * ```ts
 * import { FacebookProvider } from "@draftauth/core/provider/facebook"
 *
 * export default issuer({
 *   providers: {
 *     facebook: FacebookProvider({
 *       clientID: process.env.FACEBOOK_APP_ID,
 *       clientSecret: process.env.FACEBOOK_APP_SECRET,
 *       scopes: ["email", "public_profile", "user_friends"]
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
 * import { FacebookOidcProvider } from "@draftauth/core/provider/facebook"
 *
 * export default issuer({
 *   providers: {
 *     facebook: FacebookOidcProvider({
 *       clientID: process.env.FACEBOOK_APP_ID,
 *       scopes: ["email", "public_profile"]
 *     })
 *   }
 * })
 * ```
 *
 * ## Configuration Options
 *
 * ### OAuth 2.0 Specific
 * - Access tokens for Facebook Graph API calls
 * - Support for various Facebook permissions
 * - Access to user data, posts, friends, etc.
 *
 * ### OIDC Specific
 * - ID tokens with verified user claims
 * - Simpler setup for authentication-only use cases
 * - Perfect for basic user login
 *
 * ## Common Facebook Permissions
 *
 * - `public_profile` - Basic profile information (name, picture, etc.)
 * - `email` - User's email address
 * - `user_friends` - List of user's friends who also use your app
 * - `user_posts` - User's posts on their timeline
 * - `user_photos` - User's photos and albums
 * - `pages_read_engagement` - Read engagement data for Pages
 *
 * ## User Data Access
 *
 * ```ts
 * success: async (ctx, value) => {
 *   if (value.provider === "facebook") {
 *     // OAuth 2.0 flow
 *     if (value.tokenset) {
 *       const accessToken = value.tokenset.access
 *
 *       // Fetch user profile from Graph API
 *       const profileResponse = await fetch(
 *         `https://graph.facebook.com/me?fields=id,name,email,picture&access_token=${accessToken}`
 *       )
 *       const profile = await profileResponse.json()
 *
 *       // User info: `${profile.name} (${profile.email})`
 *       // Facebook ID: profile.id
 *     }
 *
 *     // OIDC flow
 *     if (value.id) {
 *       // Facebook user ID: value.id.sub
 *       // Verified email: value.id.email
 *       // Full name: value.id.name
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
 * Configuration options for Facebook OAuth 2.0 provider.
 * Extends the base OAuth 2.0 configuration with Facebook-specific documentation.
 */
export interface FacebookConfig extends Oauth2WrappedConfig {
	/**
	 * Facebook App ID from your Facebook App Dashboard.
	 * This is the public identifier for your Facebook application.
	 *
	 * @example
	 * ```ts
	 * {
	 *   clientID: "1234567890123456"
	 * }
	 * ```
	 */
	readonly clientID: string

	/**
	 * Facebook App Secret from your Facebook App Dashboard.
	 * Keep this secure and never expose it to client-side code.
	 *
	 * @example
	 * ```ts
	 * {
	 *   clientSecret: process.env.FACEBOOK_APP_SECRET
	 * }
	 * ```
	 */
	readonly clientSecret: string

	/**
	 * Facebook permissions to request during login.
	 * Determines what data your app can access from the user's Facebook account.
	 *
	 * @example
	 * ```ts
	 * {
	 *   scopes: [
	 *     "email",           // User's email address
	 *     "public_profile",  // Basic profile info
	 *     "user_friends",    // User's friends list
	 *     "user_posts"       // User's timeline posts
	 *   ]
	 * }
	 * ```
	 */
	readonly scopes: string[]

	/**
	 * Additional query parameters for Facebook OAuth authorization.
	 * Useful for Facebook-specific options like response type or display mode.
	 *
	 * @example
	 * ```ts
	 * {
	 *   query: {
	 *     display: "popup",           // Show login in popup
	 *     auth_type: "rerequest",     // Force permission re-request
	 *     state: "custom-state"       // Custom state parameter
	 *   }
	 * }
	 * ```
	 */
	readonly query?: Record<string, string>
}

/**
 * Configuration options for Facebook OIDC provider.
 * Extends the base OIDC configuration with Facebook-specific documentation.
 */
export interface FacebookOidcConfig extends OidcWrappedConfig {
	/**
	 * Facebook App ID from your Facebook App Dashboard.
	 * No app secret needed for OIDC flows.
	 *
	 * @example
	 * ```ts
	 * {
	 *   clientID: "1234567890123456"
	 * }
	 * ```
	 */
	readonly clientID: string

	/**
	 * Facebook permissions to request for OIDC.
	 * The 'openid' scope is automatically handled by Facebook.
	 *
	 * @example
	 * ```ts
	 * {
	 *   scopes: ["email", "public_profile"]
	 * }
	 * ```
	 */
	readonly scopes: string[]

	/**
	 * Additional query parameters for Facebook OIDC.
	 *
	 * @example
	 * ```ts
	 * {
	 *   query: {
	 *     display: "page",     // Full page display mode
	 *     locale: "en_US"      // Preferred language
	 *   }
	 * }
	 * ```
	 */
	readonly query?: Record<string, string>
}

/**
 * Creates a Facebook OAuth 2.0 authentication provider.
 * Use this when you need access tokens to call Facebook Graph API on behalf of the user.
 *
 * @param config - Facebook OAuth 2.0 configuration
 * @returns OAuth 2.0 provider configured for Facebook
 *
 * @example
 * ```ts
 * // Basic Facebook authentication
 * const basicFacebook = FacebookProvider({
 *   clientID: process.env.FACEBOOK_APP_ID,
 *   clientSecret: process.env.FACEBOOK_APP_SECRET,
 *   scopes: ["email", "public_profile"]
 * })
 *
 * // Facebook with extended permissions
 * const extendedFacebook = FacebookProvider({
 *   clientID: process.env.FACEBOOK_APP_ID,
 *   clientSecret: process.env.FACEBOOK_APP_SECRET,
 *   scopes: [
 *     "email",
 *     "public_profile",
 *     "user_friends",
 *     "user_posts",
 *     "user_photos"
 *   ],
 *   query: {
 *     display: "popup",
 *     auth_type: "rerequest" // Force permission approval
 *   }
 * })
 *
 * // Using the access token for Graph API calls
 * export default issuer({
 *   providers: { facebook: extendedFacebook },
 *   success: async (ctx, value) => {
 *     if (value.provider === "facebook") {
 *       const token = value.tokenset.access
 *
 *       // Get user profile with custom fields
 *       const profileRes = await fetch(
 *         `https://graph.facebook.com/me?fields=id,name,email,picture.width(200),friends&access_token=${token}`
 *       )
 *       const profile = await profileRes.json()
 *
 *       // Get user's posts (if permission granted)
 *       const postsRes = await fetch(
 *         `https://graph.facebook.com/me/posts?access_token=${token}`
 *       )
 *       const posts = await postsRes.json()
 *
 *       return ctx.subject("user", {
 *         facebookId: profile.id,
 *         name: profile.name,
 *         email: profile.email,
 *         picture: profile.picture?.data?.url,
 *         friendsCount: profile.friends?.summary?.total_count || 0,
 *         postsCount: posts.data?.length || 0
 *       })
 *     }
 *   }
 * })
 * ```
 */
export const FacebookProvider = (config: FacebookConfig) => {
	return Oauth2Provider({
		...config,
		type: "facebook",
		endpoint: {
			authorization: "https://www.facebook.com/v18.0/dialog/oauth",
			token: "https://graph.facebook.com/v18.0/oauth/access_token"
		}
	})
}

/**
 * Creates a Facebook OpenID Connect authentication provider.
 * Use this for simple user authentication when you only need user identity information.
 *
 * @param config - Facebook OIDC configuration
 * @returns OIDC provider configured for Facebook
 *
 * @example
 * ```ts
 * // Simple Facebook authentication
 * const simpleFacebook = FacebookOidcProvider({
 *   clientID: process.env.FACEBOOK_APP_ID,
 *   scopes: ["email", "public_profile"]
 * })
 *
 * // Facebook with custom display options
 * const customFacebook = FacebookOidcProvider({
 *   clientID: process.env.FACEBOOK_APP_ID,
 *   scopes: ["email", "public_profile"],
 *   query: {
 *     display: "popup",    // Show in popup window
 *     locale: "es_ES"      // Spanish interface
 *   }
 * })
 *
 * // Access user information from ID token
 * export default issuer({
 *   providers: { facebook: simpleFacebook },
 *   success: async (ctx, value) => {
 *     if (value.provider === "facebook") {
 *       const user = value.id
 *       // User authenticated: `${user.name} (${user.email})`
 *       // Facebook ID: user.sub
 *
 *       return ctx.subject("user", {
 *         facebookId: user.sub,
 *         name: user.name,
 *         email: user.email
 *       })
 *     }
 *   }
 * })
 * ```
 */
export const FacebookOidcProvider = (config: FacebookOidcConfig) => {
	return OidcProvider({
		...config,
		type: "facebook",
		issuer: "https://www.facebook.com"
	})
}
