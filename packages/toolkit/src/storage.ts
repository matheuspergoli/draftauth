export interface PkceState {
	state: string
	verifier: string
	provider: string
}

export interface AuthStorage {
	set(state: PkceState): void
	get(): PkceState | null
	clear(): void
}

const DRAFT_STORAGE_KEY = "draftauth.pkce"

export const createBrowserSessionStorage = (): AuthStorage => ({
	set: (data: PkceState): void => {
		if (typeof sessionStorage !== "undefined") {
			sessionStorage.setItem(DRAFT_STORAGE_KEY, JSON.stringify(data))
		}
	},
	get: (): PkceState | null => {
		if (typeof sessionStorage !== "undefined") {
			const data = sessionStorage.getItem(DRAFT_STORAGE_KEY)
			return data ? (JSON.parse(data) as PkceState) : null
		}
		return null
	},
	clear: (): void => {
		if (typeof sessionStorage !== "undefined") {
			sessionStorage.removeItem(DRAFT_STORAGE_KEY)
		}
	}
})
