import type { ClientStrategy } from "./strategy"

export const GitHubStrategy: ClientStrategy = {
	name: "facebook",
	authorizationEndpoint: "https://www.facebook.com/v19.0/dialog/oauth",
	tokenEndpoint: "https://graph.facebook.com/v19.0/oauth/access_token",
	defaultScopes: ["public_profile", "email"]
}
