import { env } from "@/environment/env"
import type { ApiRoutes } from "@draftauth/types"
import { hc } from "hono/client"
import { toast } from "sonner"

import { auth } from "./auth"

const customFetch = async (input: RequestInfo | URL, init?: RequestInit) => {
	const authStatus = await auth.checkAuthStatus()

	if (!authStatus.isAuthenticated) {
		auth.login()
		throw new Error("Autenticação obrigatória")
	}

	const headers = {
		...init?.headers,
		Authorization: `Bearer ${authStatus.accessToken}`
	}

	const data = await fetch(input, { ...init, headers })

	if (!data.ok) {
		const res = await data.text()

		if (data.status === 401) {
			const refreshedToken = await auth.refreshTokens()
			if (refreshedToken) {
				const retryHeaders = {
					...init?.headers,
					Authorization: `Bearer ${refreshedToken}`
				}

				const retryData = await fetch(input, { ...init, headers: retryHeaders })

				if (retryData.ok) {
					return retryData
				}

				const retryRes = await retryData.text()
				toast.error(retryRes)
				throw new Error(retryRes)
			}
		}

		toast.error(res)
		throw new Error(res)
	}

	return data
}

export const api = hc<ApiRoutes>(env.VITE_BACKEND_URL, {
	fetch: customFetch
}).api
