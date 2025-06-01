import { z } from "zod"

const GithubUser = z.object({
	name: z.string(),
	avatar_url: z.string(),
	email: z.string().email().nullable(),
	id: z.number().transform((arg) => String(arg))
})

const getGithubEmail = async ({ accessToken }: { accessToken: string }) => {
	const res = await fetch("https://api.github.com/user/emails", {
		headers: { Authorization: `token ${accessToken}` }
	})

	const emails = (await res.json()) as { email: string; primary: boolean }[]
	const primaryEmail = emails.find((email) => email.primary)?.email

	if (!primaryEmail) {
		throw new Error("Primary email not found")
	}

	return primaryEmail
}

export const getGithubUser = async ({ accessToken }: { accessToken: string }) => {
	const githubUserResponse = await fetch("https://api.github.com/user", {
		headers: {
			Authorization: `Bearer ${accessToken}`
		}
	})

	const githubUserUnparsed = await githubUserResponse.json()
	const githubUserParsed = GithubUser.safeParse(githubUserUnparsed)

	if (!githubUserParsed.success) {
		throw new Error("Error parsing github user")
	}

	const githubUser = {
		...githubUserParsed.data,
		email: githubUserParsed.data.email ?? (await getGithubEmail({ accessToken }))
	}

	return githubUser
}

const GoogleUser = z.object({
	sub: z.string(),
	name: z.string(),
	picture: z.string(),
	email: z.string().email()
})

export const getGoogleUser = async ({ accessToken }: { accessToken: string }) => {
	const googleUserResponse = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
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
