import { env } from "@/environment/env"
import type { ApiRoutes } from "@draftauth/types"
import { hc } from "hono/client"
import { toast } from "sonner"

import { auth } from "./auth"

const customFetch = async (input: RequestInfo | URL, init?: RequestInit) => {
	const data = await fetch(input, init)

	if (!data.ok) {
		const res = await data.text()

		toast.error(res)

		throw new Error(res)
	}

	return data
}

export const api = hc<ApiRoutes>(env.VITE_BACKEND_URL, {
	fetch: customFetch,
	headers: {
		Authorization: `Bearer ${auth.tokenStorage.getAccessToken()}`
	}
}).api
