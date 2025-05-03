import { randomBytes } from "node:crypto"
import { dbClient } from "@/db/client"
import type { UserStatus } from "@/db/schema"
import { env } from "@/environment/env"
import { isValidApplicationClient } from "@/services/application-service"
import { isSetupComplete } from "@/services/config-service"
import {
	createUser,
	findOrCreateUser,
	findUserByEmail,
	linkExternalIdentity,
	setUserGlobalStatus
} from "@/services/user-service"
import { createClient } from "@draftauth/core/client"
import { issuer } from "@draftauth/core/issuer"
import {
	GithubProvider,
	GoogleProvider,
	PasswordProvider,
	PasswordUI
} from "@draftauth/core/providers"
import { TursoStorage } from "@draftauth/core/storage/turso"
import { createSubjects } from "@draftauth/core/subjects"
import { CUSTOM_THEME } from "@draftauth/core/themes/custom-theme"
import { AccessDeniedPage } from "@draftauth/core/ui/access-denied-page"
import { CustomSelect } from "@draftauth/core/ui/custom-select"
import { UserNotFoundPage } from "@draftauth/core/ui/user-not-found-page"
import { getGithubUser } from "@draftauth/core/utils/github"
import { getGoogleUser } from "@draftauth/core/utils/google"
import { getBaseUrl } from "@draftauth/utils"
import { getContext } from "hono/context-storage"
import { z } from "zod"

export const authClient = createClient({
	issuer: getBaseUrl(),
	clientID: "draftauth-api-verifier"
})

export const subjects = createSubjects({
	user: z.object({
		id: z.string(),
		email: z.string()
	})
})

const handleGoogleLogin = async ({ accessToken }: { accessToken: string }) => {
	const googleUser = await getGoogleUser({ accessToken })

	return findOrCreateUser({
		providerName: "google",
		providerUserId: googleUser.sub,
		verifiedEmail: googleUser.email
	})
}

const handleGithubLogin = async ({ accessToken }: { accessToken: string }) => {
	const githubUser = await getGithubUser({ accessToken })

	return findOrCreateUser({
		providerName: "github",
		providerUserId: githubUser.id,
		verifiedEmail: githubUser.email
	})
}

const handlePasswordLogin = async (data: { email: string }) => {
	let centralUser = await findUserByEmail({ email: data.email })

	if (centralUser) {
		await linkExternalIdentity({
			providerName: "password",
			providerUserId: data.email,
			userId: centralUser.userId
		})

		return centralUser
	}

	centralUser = await createUser({ email: data.email, initialStatus: "active" })
	await linkExternalIdentity({
		providerName: "password",
		providerUserId: data.email,
		userId: centralUser.userId
	})

	return centralUser
}

export const auth = issuer({
	subjects,
	theme: CUSTOM_THEME,
	select: CustomSelect(),
	storage: TursoStorage(dbClient),
	providers: {
		password: PasswordProvider(
			PasswordUI({
				copy: {
					login: "Entrar",
					input_email: "Email",
					input_code: "Código",
					register: "Cadastrar",
					input_password: "Senha",
					button_continue: "Continuar",
					login_prompt: "Já tem uma conta?",
					change_prompt: "Esqueceu a senha?",
					error_invalid_code: "Código inválido",
					error_invalid_email: "Email inválido",
					register_prompt: "Não tem uma conta?",
					input_repeat: "Digite a senha novamente",
					error_invalid_password: "Senha inválida",
					error_password_mismatch: "Repita a senha corretamente",
					error_email_taken: "Já existe uma conta com esse email"
				},
				sendCode: async (email, code) => {
					console.log(email, code)
				},
				validatePassword: (password) => {
					if (password.length < 8) {
						return "Senha deve ter no mínimo 8 caracteres"
					}

					return
				}
			})
		),
		github: GithubProvider({
			scopes: ["user:email", "profile"],
			clientID: env.GITHUB_CLIENT_ID,
			clientSecret: env.GITHUB_CLIENT_SECRET
		}),
		google: GoogleProvider({
			scopes: ["email", "profile"],
			clientID: env.GOOGLE_CLIENT_ID,
			clientSecret: env.GOOGLE_CLIENT_SECRET
		})
	},
	async allow({ clientID, redirectURI }) {
		const setupComplete = await isSetupComplete()

		if (!setupComplete) return true

		return await isValidApplicationClient({ clientId: clientID, redirectUri: redirectURI })
	},
	success: async (ctx, value) => {
		const context = getContext()
		const setupComplete = await isSetupComplete()
		let centralUser: { userId: string; email: string; status: UserStatus } | null = null

		if (!setupComplete) {
			let firstUser: { userId: string; email: string; status: UserStatus } | null = null

			if (value.provider === "github") {
				firstUser = await handleGithubLogin({ accessToken: value.tokenset.access })
			}

			if (value.provider === "google") {
				firstUser = await handleGoogleLogin({ accessToken: value.tokenset.access })
			}

			if (value.provider === "password") {
				firstUser = await handlePasswordLogin({ email: value.email })
			}

			if (!firstUser) {
				return context.html(UserNotFoundPage())
			}

			if (firstUser.status !== "active") {
				await setUserGlobalStatus({ userId: firstUser.userId, status: "active" })
			}

			const setupState = randomBytes(32).toString("hex")
			const storage = TursoStorage(dbClient)
			const stateKey = ["setup_state", setupState]
			const stateValue = { userId: firstUser.userId }
			const expirySeconds = 10 * 60

			await storage.set(stateKey, stateValue, new Date(Date.now() + expirySeconds * 1000))

			const setupUrl = new URL("/setup", env.FRONTEND_URL)
			setupUrl.searchParams.set("state", setupState)

			return context.redirect(setupUrl.toString(), 302)
		}

		if (value.provider === "github") {
			centralUser = await handleGithubLogin({ accessToken: value.tokenset.access })
		}

		if (value.provider === "google") {
			centralUser = await handleGoogleLogin({ accessToken: value.tokenset.access })
		}

		if (value.provider === "password") {
			centralUser = await handlePasswordLogin({ email: value.email })
		}

		if (!centralUser) {
			return context.html(UserNotFoundPage())
		}

		if (centralUser.status !== "active") {
			return context.html(AccessDeniedPage())
		}

		return ctx.subject("user", {
			id: centralUser.userId,
			email: centralUser.email
		})
	}
})
