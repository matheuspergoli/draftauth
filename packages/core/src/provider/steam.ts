import type { Context } from "hono"
import { getRelativeUrl } from "../util"
import type { Provider } from "./provider"

export interface SteamProviderConfig {
	apiKey: string
	realm: string
}

export const SteamProvider = (config: SteamProviderConfig): Provider<{ steamId: string }> => {
	return {
		type: "steam",
		init(routes, ctx) {
			const STEAM_LOGIN_URL = "https://steamcommunity.com/openid/login"

			routes.get("/authorize", async (c: Context) => {
				const returnTo = getRelativeUrl(c, "./callback")

				const params = new URLSearchParams({
					"openid.ns": "http://specs.openid.net/auth/2.0",
					"openid.mode": "checkid_setup",
					"openid.return_to": returnTo,
					"openid.realm": config.realm,
					"openid.identity": "http://specs.openid.net/auth/2.0/identifier_select",
					"openid.claimed_id": "http://specs.openid.net/auth/2.0/identifier_select"
				})

				const redirectUrl = `${STEAM_LOGIN_URL}?${params.toString()}`
				return c.redirect(redirectUrl)
			})

			routes.get("/callback", async (c: Context) => {
				const queryParams = new URL(c.req.url).searchParams
				const allParams: Record<string, string> = {}
				queryParams.forEach((value, key) => {
					allParams[key] = value
				})

				const verificationPayload = new URLSearchParams({
					...allParams,
					"openid.mode": "check_authentication"
				})

				const verificationResponse = await fetch(STEAM_LOGIN_URL, {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded"
					},
					body: verificationPayload.toString()
				})

				const responseText = await verificationResponse.text()

				if (responseText.includes("is_valid:true")) {
					const claimedId = allParams["openid.claimed_id"]
					if (!claimedId) {
						throw new Error("Steam response is missing 'openid.claimed_id'.")
					}

					const steamIdMatch = claimedId.match(
						/https:\/\/steamcommunity\.com\/openid\/id\/(\d+)/
					)

					if (steamIdMatch?.[1]) {
						const steamId = steamIdMatch[1]

						return await ctx.success(c, { steamId })
					}
				}

				throw new Error("Steam authentication failed: Invalid signature.")
			})
		}
	}
}
