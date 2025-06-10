import type { ClientStrategy } from "./strategy"

export const GitHubStrategy: ClientStrategy = {
	name: "github",
	authorizationEndpoint: "https://github.com/login/oauth/authorize",
	tokenEndpoint: "https://github.com/login/oauth/access_token",
	userinfoEndpoint: "https://api.github.com/user",
	defaultScopes: ["read:user", "user:email"]
}
