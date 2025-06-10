import type { ClientStrategy, UserProfile } from "./strategy"

export interface GitHubProfile {
	id: number
	login: string
	name: string | null
	email: string | null
	avatar_url: string
	[key: string]: unknown
}

export const GitHubStrategy: ClientStrategy<GitHubProfile> = {
	name: "github",
	authorizationEndpoint: "https://github.com/login/oauth/authorize",
	tokenEndpoint: "https://github.com/login/oauth/access_token",
	userinfoEndpoint: "https://api.github.com/user",
	defaultScopes: ["read:user", "user:email"],

	isProfile(data: unknown): data is GitHubProfile {
		return (
			typeof data === "object" &&
			data !== null &&
			"id" in data &&
			typeof (data as GitHubProfile).id === "number" &&
			"login" in data &&
			typeof (data as GitHubProfile).login === "string"
		)
	},

	normalizeProfile(rawProfile: GitHubProfile): UserProfile {
		return {
			id: rawProfile.id.toString(),
			name: rawProfile.name,
			email: rawProfile.email,
			picture: rawProfile.avatar_url,
			raw: rawProfile
		}
	}
}
