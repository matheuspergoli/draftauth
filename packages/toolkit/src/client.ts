import { generatePKCE } from "./pkce"
import type { ClientStrategy, OAuth2TokenResponse, UserProfile } from "./providers/strategy"
import { type AuthStorage, createBrowserSessionStorage } from "./storage"

export type ClientConfig<TStrategies extends Record<string, ClientStrategy>> = {
	[K in keyof TStrategies]: {
		clientId: string
		redirectUri: string
	}
}

export interface LoginOptions {
	scopes?: string[]
}

export interface HandleRedirectResult {
	provider: string
	accessToken: string
	profile: UserProfile
}

export const createClient = <TStrategies extends Record<string, ClientStrategy>>({
	config,
	strategies,
	storage
}: {
	config: ClientConfig<TStrategies>
	strategies: TStrategies
	storage?: AuthStorage
}) => {
	const pkceStorage = storage || createBrowserSessionStorage()

	const login = async (
		providerName: keyof TStrategies,
		options?: LoginOptions
	): Promise<{ url: string }> => {
		const strategy = strategies[providerName]
		const providerConfig = config[providerName]

		if (!strategy || !providerConfig) {
			throw new Error(`Provider '${String(providerName)}' not configured or not supported.`)
		}

		const state = crypto.randomUUID()
		const pkce = await generatePKCE()

		pkceStorage.set({ state, verifier: pkce.verifier, provider: String(providerName) })

		const scopes = options?.scopes || strategy.defaultScopes
		const params = new URLSearchParams({
			client_id: providerConfig.clientId,
			redirect_uri: providerConfig.redirectUri,
			response_type: "code",
			scope: scopes.join(" "),
			state: state,
			code_challenge: pkce.challenge,
			code_challenge_method: "S256"
		})

		const url = `${strategy.authorizationEndpoint}?${params.toString()}`
		return { url }
	}

	const handleRedirect = async (redirectUrl: string): Promise<HandleRedirectResult> => {
		const params = new URL(redirectUrl).searchParams
		const code = params.get("code")
		const state = params.get("state")

		const storedPkce = pkceStorage.get()
		pkceStorage.clear()

		if (!code || !state || !storedPkce) {
			throw new Error("Invalid callback URL: missing code, state, or stored PKCE data.")
		}
		if (state !== storedPkce.state) {
			throw new Error("State mismatch (CSRF check failed).")
		}

		const strategy = strategies[storedPkce.provider]
		const providerConfig = config[storedPkce.provider]

		if (!strategy || !providerConfig) {
			throw new Error(`Provider '${storedPkce.provider}' from callback not configured.`)
		}

		const tokenResponse = await fetch(strategy.tokenEndpoint, {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
				Accept: "application/json"
			},
			body: new URLSearchParams({
				grant_type: "authorization_code",
				code: code,
				redirect_uri: providerConfig.redirectUri,
				client_id: providerConfig.clientId,
				code_verifier: storedPkce.verifier,
				client_secret: "f185643b7718ea7fa85fbbdd33be2093de5cf679"
			})
		})

		if (!tokenResponse.ok) {
			throw new Error(`Token exchange failed: ${await tokenResponse.text()}`)
		}

		const tokenData = (await tokenResponse.json()) as OAuth2TokenResponse
		const accessToken = tokenData.access_token

		const profileResponse = await fetch(strategy.userinfoEndpoint, {
			headers: { Authorization: `Bearer ${accessToken}` }
		})

		if (!profileResponse.ok) {
			throw new Error(`User profile fetch failed: ${await profileResponse.text()}`)
		}

		const rawProfile = await profileResponse.json()

		if (strategy.isProfile(rawProfile)) {
			const profile = strategy.normalizeProfile(rawProfile)

			return {
				provider: storedPkce.provider,
				accessToken,
				profile
			}
		}

		throw new Error(
			`Received profile data for '${storedPkce.provider}' does not match expected format.`
		)
	}

	return { login, handleRedirect }
}
