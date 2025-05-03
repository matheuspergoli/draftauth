import { z } from "zod"

const OAUTH_FETCH_URL = "https://openidconnect.googleapis.com/v1/userinfo"

const GoogleUser = z.object({
	sub: z.string(),
	name: z.string(),
	picture: z.string(),
	email: z.string().email()
})

export const getGoogleUser = async ({ accessToken }: { accessToken: string }) => {
	const googleUserResponse = await fetch(OAUTH_FETCH_URL, {
		headers: {
			Authorization: `Bearer ${accessToken}`
		}
	})

	const googleUserUnparsed = await googleUserResponse.json()
	const googleUserParsed = GoogleUser.safeParse(googleUserUnparsed)

	if (!googleUserParsed.success) {
		throw new Error("Error parsing google user")
	}

	return googleUserParsed.data
}
