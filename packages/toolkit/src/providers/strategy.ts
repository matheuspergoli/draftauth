export interface UserProfile {
	id: string
	name: string | null
	email: string | null
	picture: string | null
	raw: Record<string, unknown>
}

export interface OAuth2TokenResponse {
	access_token: string
	token_type: string
}

export interface ClientStrategy<
	TRawProfile extends Record<string, unknown> = Record<string, unknown>
> {
	readonly name: string
	readonly authorizationEndpoint: string
	readonly tokenEndpoint: string
	readonly userinfoEndpoint: string
	readonly defaultScopes: string[]

	isProfile(data: unknown): data is TRawProfile

	normalizeProfile(rawProfile: TRawProfile): UserProfile
}
