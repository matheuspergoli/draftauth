import { randomBytes } from "node:crypto"
import { dbClient } from "@/db/client"
import { env } from "@/environment/env"
import { setUserAppAccessStatus } from "@/services/access-service"
import { isValidApplicationClient } from "@/services/application-service"
import { isSetupComplete } from "@/services/config-service"
import {
	type FindOrCreateUserResult,
	createUser,
	findOrCreateUser,
	findUserByEmail,
	linkExternalIdentity,
	setUserGlobalStatus
} from "@/services/user-service"
import { createClient } from "@draftauth/core/client"
import { issuer } from "@draftauth/core/issuer"
import {
	CodeProvider,
	CodeUI,
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
import { VerificationCodeEmail } from "@draftauth/emails/verification-code-email"
import { getBaseUrl } from "@draftauth/utils"
import { getConnInfo } from "hono/bun"
import { getContext } from "hono/context-storage"
import { HTTPException } from "hono/http-exception"
import { z } from "zod"
import { checkPasswordLeaks, checkPasswordStrength, translateWarnings } from "./password"
import { resend } from "./resend"

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

const handleCodeLogin = async (data: { email: string }) => {
	let centralUser = await findUserByEmail({ email: data.email })

	if (centralUser) {
		await linkExternalIdentity({
			providerName: "code",
			providerUserId: data.email,
			userId: centralUser.userId
		})
		return { user: centralUser, created: false }
	}

	centralUser = await createUser({ email: data.email, initialStatus: "active" })
	await linkExternalIdentity({
		providerName: "code",
		providerUserId: data.email,
		userId: centralUser.userId
	})

	return { user: centralUser, created: true }
}

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

		return { user: centralUser, created: false }
	}

	centralUser = await createUser({ email: data.email, initialStatus: "active" })
	await linkExternalIdentity({
		providerName: "password",
		providerUserId: data.email,
		userId: centralUser.userId
	})

	return { user: centralUser, created: true }
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
					const c = getContext()
					const info = getConnInfo(c)
					const limitIp = c.get("ipRateLimiter")
					const limitEmail = c.get("emailRateLimiter")

					const ipResult = await limitIp(info.remote.address ?? "ip:unknown")
					if (!ipResult.success) {
						throw new HTTPException(429, {
							message: "Muitas tentativas do seu endereço IP. Tente novamente mais tarde."
						})
					}

					const emailResult = await limitEmail(email)
					if (!emailResult.success) {
						throw new HTTPException(429, {
							message: "Muitas tentativas para este email. Tente novamente mais tarde."
						})
					}

					await resend.emails.send({
						to: [email],
						subject: "Confirmação de Email",
						from: "Draft Auth <welcome@draftauth.com.br>",
						react: VerificationCodeEmail({ verificationCode: code })
					})
				},
				validatePassword: async (password) => {
					if (password.length < 6) return "Senha deve ter no mínimo 6 caracteres"
					const { feedback } = checkPasswordStrength(password)
					if (feedback.warning) return translateWarnings(feedback.warning)
					const checkForPasswordLeaks = await checkPasswordLeaks(password)
					if (checkForPasswordLeaks) return "Essa senha foi vazada em uma violação de dados"
					return undefined
				}
			})
		),
		code: CodeProvider(
			CodeUI({
				copy: {
					code_placeholder: "Código",
					button_continue: "Continuar",
					code_invalid: "Código inválido",
					code_resend: "Enviar novamente",
					code_sent: "Código enviado para ",
					code_didnt_get: "Não recebeu o código?",
					code_info: "Nós enviaremos um código para seu email."
				},
				async sendCode(claims, code) {
					const c = getContext()
					const info = getConnInfo(c)
					const limitIp = c.get("ipRateLimiter")
					const limitEmail = c.get("emailRateLimiter")

					if (!claims.email) {
						throw new HTTPException(400, {
							message: "Erro ao enviar código PIN para email"
						})
					}

					const ipResult = await limitIp(info.remote.address ?? "ip:unknown")
					if (!ipResult.success) {
						throw new HTTPException(429, {
							message: "Muitas tentativas do seu endereço IP. Tente novamente mais tarde."
						})
					}

					const emailResult = await limitEmail(claims.email)
					if (!emailResult.success) {
						throw new HTTPException(429, {
							message: "Muitas tentativas para este email. Tente novamente mais tarde."
						})
					}

					await resend.emails.send({
						to: [claims.email],
						subject: "Confirmação de Email",
						from: "Draft Auth <welcome@draftauth.com.br>",
						react: VerificationCodeEmail({ verificationCode: code })
					})
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
		getContext().set("currentAppId", clientID)
		const setupComplete = await isSetupComplete()

		if (!setupComplete) return true

		return await isValidApplicationClient({ clientId: clientID, redirectUri: redirectURI })
	},
	success: async (ctx, value) => {
		const context = getContext()
		const setupComplete = await isSetupComplete()
		const currentAppId = context.get("currentAppId")
		let centralUser: FindOrCreateUserResult | null = null

		if (!setupComplete) {
			let firstUser: FindOrCreateUserResult | null = null

			if (value.provider === "code") {
				if (!value.claims.email) return context.html(UserNotFoundPage())
				firstUser = await handleCodeLogin({ email: value.claims.email })
			}

			if (value.provider === "github") {
				firstUser = await handleGithubLogin({ accessToken: value.tokenset.access })
			}

			if (value.provider === "google") {
				firstUser = await handleGoogleLogin({ accessToken: value.tokenset.access })
			}

			if (value.provider === "password") {
				firstUser = await handlePasswordLogin({ email: value.email })
			}

			if (!firstUser?.user) {
				return context.html(UserNotFoundPage())
			}

			if (firstUser.user.status !== "active") {
				await setUserGlobalStatus({ userId: firstUser.user.userId, status: "active" })
			}

			if (firstUser.created && currentAppId) {
				await setUserAppAccessStatus({
					status: "enabled",
					appId: currentAppId,
					userId: firstUser.user.userId
				})
			}

			const setupState = randomBytes(32).toString("hex")
			const storage = TursoStorage(dbClient)
			const stateKey = ["setup_state", setupState]
			const stateValue = { userId: firstUser.user.userId }
			const expirySeconds = 10 * 60

			await storage.set(stateKey, stateValue, new Date(Date.now() + expirySeconds * 1000))

			const setupUrl = new URL("/setup", env.FRONTEND_URL)
			setupUrl.searchParams.set("state", setupState)

			return context.redirect(setupUrl.toString(), 302)
		}

		if (value.provider === "code") {
			if (!value.claims.email) return context.html(UserNotFoundPage())
			centralUser = await handleCodeLogin({ email: value.claims.email })
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

		if (!centralUser?.user) {
			return context.html(UserNotFoundPage())
		}

		if (centralUser.user.status !== "active") {
			return context.html(AccessDeniedPage())
		}

		if (centralUser.created && currentAppId) {
			await setUserAppAccessStatus({
				status: "enabled",
				appId: currentAppId,
				userId: centralUser.user.userId
			})
		}

		return ctx.subject("user", {
			id: centralUser.user.userId,
			email: centralUser.user.email
		})
	}
})
