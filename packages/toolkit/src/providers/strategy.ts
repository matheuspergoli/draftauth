export interface OAuth2TokenResponse {
	access_token: string
}

export interface ClientStrategy {
	readonly name: string
	readonly authorizationEndpoint: string
	readonly tokenEndpoint: string
	readonly defaultScopes: string[]
}
