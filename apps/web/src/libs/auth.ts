import { env } from "@/environment/env"
import { createClient } from "@draftauth/core/client"
import { z } from "zod"
import { queryClient } from "./query-client"

const ACCESS_KEY = "access_token"
const REFRESH_KEY = "refresh_token"
const CHALLENGE_KEY = "challenge_token"

const ChallengeSchema = z.object({
	state: z.string(),
	verifier: z.string()
})

const client = createClient({
	issuer: env.VITE_BACKEND_URL,
	clientID: env.VITE_APPLICATION_ID
})

const tokenStorage = {
	getChallengeToken: () => sessionStorage.getItem(CHALLENGE_KEY),
	setChallengeToken: (token: string) => sessionStorage.setItem(CHALLENGE_KEY, token),
	removeChallengeToken: () => sessionStorage.removeItem(CHALLENGE_KEY),

	getRefreshToken: () => localStorage.getItem(REFRESH_KEY),
	setRefreshToken: (token: string) => localStorage.setItem(REFRESH_KEY, token),
	removeRefreshToken: () => localStorage.removeItem(REFRESH_KEY),

	getAccessToken: () => localStorage.getItem(ACCESS_KEY),
	setAccessToken: (token: string) => localStorage.setItem(ACCESS_KEY, token),
	removeAccessToken: () => localStorage.removeItem(ACCESS_KEY),

	clearTokens: () => {
		localStorage.removeItem(ACCESS_KEY)
		localStorage.removeItem(REFRESH_KEY)
		sessionStorage.removeItem(CHALLENGE_KEY)
	}
}

const login = async () => {
	const result = await client.authorize(location.origin, "code", {
		pkce: true
	})

	if (!result.success) return null

	tokenStorage.setChallengeToken(JSON.stringify(result.data.challenge))
	location.href = result.data.url
	return
}

const logout = async () => {
	tokenStorage.clearTokens()
	await queryClient.invalidateQueries()
}

const callback = async ({ code, state }: { code: string; state: string }) => {
	const unparsedChallenge = JSON.parse(tokenStorage.getChallengeToken() ?? "{}")
	tokenStorage.removeChallengeToken()

	const parsedChallenge = ChallengeSchema.safeParse(unparsedChallenge)
	if (!parsedChallenge.success) {
		return { success: false, error: "challenge_parse_error" }
	}

	if (!code) {
		return { success: false, error: "no_code" }
	}

	const { data: challenge } = parsedChallenge
	if (state !== challenge.state || !challenge.verifier) {
		return { success: false, error: "invalid_callback_state" }
	}

	const exchanged = await client.exchange(code, location.origin, challenge.verifier)
	if (!exchanged.success) {
		return { success: false, error: "token_exchange_failed" }
	}

	tokenStorage.setAccessToken(exchanged.data.access)
	tokenStorage.setRefreshToken(exchanged.data.refresh)
	await queryClient.invalidateQueries()

	return { success: true }
}

const refreshTokens = async () => {
	const storedAccessToken = tokenStorage.getAccessToken()
	const storedRefreshToken = tokenStorage.getRefreshToken()

	if (!storedRefreshToken) return null

	try {
		const result = await client.refresh(storedRefreshToken, {
			access: storedAccessToken ?? undefined
		})

		if (!result.success) return null

		if (result.data.tokens) {
			tokenStorage.setAccessToken(result.data.tokens.access)
			tokenStorage.setRefreshToken(result.data.tokens.refresh)
			await queryClient.invalidateQueries()
			return result.data.tokens.access
		}

		return storedAccessToken
	} catch (error) {
		return null
	}
}

const checkAuthStatus = async (): Promise<
	| { isAuthenticated: true; accessToken: string }
	| { isAuthenticated: false; accessToken: null }
> => {
	const storedRefreshToken = tokenStorage.getRefreshToken()
	if (!storedRefreshToken) {
		tokenStorage.clearTokens()
		return { isAuthenticated: false, accessToken: null }
	}

	const currentValidAccessToken = await refreshTokens()
	if (currentValidAccessToken) {
		return { isAuthenticated: true, accessToken: currentValidAccessToken }
	}

	tokenStorage.clearTokens()
	return { isAuthenticated: false, accessToken: null }
}

export const auth = {
	client,
	login,
	logout,
	callback,
	tokenStorage,
	refreshTokens,
	checkAuthStatus
}
