import type { Context } from "hono"
import { getRelativeUrl } from "../util"
import type { Provider } from "./provider"

/**
 * Steam OpenID authentication provider for Draft Auth.
 * Implements Steam's OpenID 2.0 authentication flow for gaming applications.
 *
 * ## Configuration
 *
 * ```ts
 * import { SteamProvider } from "@draftauth/core/provider/steam"
 *
 * const steamProvider = SteamProvider({
 *   apiKey: process.env.STEAM_API_KEY,
 *   realm: "https://myapp.com"
 * })
 *
 * export default issuer({
 *   providers: {
 *     steam: steamProvider
 *   },
 *   // ...
 * })
 * ```
 *
 * ## User Data
 *
 * The provider returns the user's Steam ID, which can be used to fetch
 * additional profile information via Steam's Web API.
 *
 * ```ts
 * success: async (ctx, value) => {
 *   if (value.provider === "steam") {
 *     // Steam user ID (17-digit number): value.steamId
 *     // Use steamId to fetch profile data from Steam API
 *   }
 * }
 * ```
 */

/**
 * Configuration options for the Steam authentication provider.
 */
export interface SteamProviderConfig {
	/**
	 * Steam Web API key for additional API calls.
	 * Required for OpenID realm validation.
	 */
	readonly apiKey: string

	/**
	 * OpenID realm that identifies your application.
	 * Should match your application's domain.
	 *
	 * @example "https://myapp.com"
	 */
	readonly realm: string
}

/**
 * User data returned by successful Steam authentication.
 */
export interface SteamUserData {
	/** Steam user ID (64-bit Steam ID as string) */
	readonly steamId: string
}

/**
 * Creates a Steam OpenID authentication provider.
 * Implements the Steam OpenID 2.0 flow for user authentication.
 *
 * @param config - Steam provider configuration
 * @returns Provider instance implementing Steam authentication
 *
 * @example
 * ```ts
 * const provider = SteamProvider({
 *   apiKey: "your-steam-api-key",
 *   realm: "https://yourdomain.com"
 * })
 *
 * // The provider will handle:
 * // - Redirecting users to Steam login
 * // - Verifying OpenID responses
 * // - Extracting Steam user ID
 * ```
 */
export const SteamProvider = (config: SteamProviderConfig): Provider<SteamUserData> => {
	/** Steam's OpenID authentication endpoint */
	const STEAM_LOGIN_URL = "https://steamcommunity.com/openid/login"

	/** Regular expression to extract Steam ID from claimed_id */
	const STEAM_ID_REGEX = /https:\/\/steamcommunity\.com\/openid\/id\/(\d+)/

	return {
		type: "steam",

		init(routes, ctx) {
			/**
			 * Initiates Steam OpenID authentication flow.
			 * Redirects user to Steam's login page with proper OpenID parameters.
			 */
			routes.get("/authorize", async (c: Context) => {
				const returnTo = getRelativeUrl(c, "./callback")

				const openIdParams = new URLSearchParams({
					"openid.ns": "http://specs.openid.net/auth/2.0",
					"openid.mode": "checkid_setup",
					"openid.return_to": returnTo,
					"openid.realm": config.realm,
					"openid.identity": "http://specs.openid.net/auth/2.0/identifier_select",
					"openid.claimed_id": "http://specs.openid.net/auth/2.0/identifier_select"
				})

				const redirectUrl = `${STEAM_LOGIN_URL}?${openIdParams.toString()}`
				return c.redirect(redirectUrl)
			})

			/**
			 * Handles Steam OpenID callback and validates the response.
			 * Verifies the OpenID signature and extracts the Steam user ID.
			 */
			routes.get("/callback", async (c: Context) => {
				const queryParams = new URL(c.req.url).searchParams

				// Convert URLSearchParams to plain object for easier manipulation
				const openIdResponse: Record<string, string> = {}
				queryParams.forEach((value, key) => {
					openIdResponse[key] = value
				})

				// Verify the OpenID response with Steam
				const verificationParams = new URLSearchParams({
					...openIdResponse,
					"openid.mode": "check_authentication"
				})

				try {
					const verificationResponse = await fetch(STEAM_LOGIN_URL, {
						method: "POST",
						headers: {
							"Content-Type": "application/x-www-form-urlencoded",
							Accept: "text/plain"
						},
						body: verificationParams.toString()
					})

					if (!verificationResponse.ok) {
						throw new Error(
							`Steam verification failed with status: ${verificationResponse.status}`
						)
					}

					const responseText = await verificationResponse.text()

					// Check if Steam validated the response
					if (!responseText.includes("is_valid:true")) {
						throw new Error("Steam authentication failed: Invalid OpenID signature")
					}

					// Extract Steam ID from the claimed_id
					const claimedId = openIdResponse["openid.claimed_id"]
					if (!claimedId) {
						throw new Error("Steam response missing required 'openid.claimed_id' parameter")
					}

					const steamIdMatch = claimedId.match(STEAM_ID_REGEX)
					const steamId = steamIdMatch?.[1]

					if (!steamId) {
						throw new Error("Unable to extract Steam ID from claimed_id")
					}

					// Return successful authentication with Steam user data
					return await ctx.success(c, { steamId })
				} catch (error) {
					throw new Error(
						error instanceof Error
							? `Steam authentication failed: ${error.message}`
							: "Steam authentication failed: Unknown error"
					)
				}
			})
		}
	}
}
