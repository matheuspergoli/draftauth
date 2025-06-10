import type { ClientStrategy } from "./strategy"

export const GoogleStrategy: ClientStrategy = {
	name: "google",
	authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
	tokenEndpoint: "https://oauth2.googleapis.com/token",
	userinfoEndpoint: "https://www.googleapis.com/oauth2/v3/userinfo",
	defaultScopes: ["openid", "email", "profile"]
}
