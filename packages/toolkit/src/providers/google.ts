import type { ClientStrategy, UserProfile } from "./strategy"

export interface GoogleProfile {
	sub: string
	name?: string
	given_name?: string
	family_name?: string
	picture?: string
	email?: string
	email_verified?: boolean
	locale?: string
	[key: string]: unknown
}

export const GoogleStrategy: ClientStrategy<GoogleProfile> = {
	name: "google",
	authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
	tokenEndpoint: "https://oauth2.googleapis.com/token",
	userinfoEndpoint: "https://www.googleapis.com/oauth2/v3/userinfo",
	defaultScopes: ["openid", "email", "profile"],

	isProfile(data): data is GoogleProfile {
		return (
			typeof data === "object" &&
			data !== null &&
			"sub" in data &&
			typeof (data as GoogleProfile).sub === "string"
		)
	},

	normalizeProfile(rawProfile: GoogleProfile): UserProfile {
		return {
			id: rawProfile.sub,
			name: rawProfile.name ?? null,
			email: rawProfile.email ?? null,
			picture: rawProfile.picture ?? null,
			raw: rawProfile
		}
	}
}
