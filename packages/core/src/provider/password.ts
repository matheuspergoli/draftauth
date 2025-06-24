import type { StandardSchemaV1 } from "@standard-schema/spec"
import { UnknownStateError } from "../error"
import { generateUnbiasedDigits, timingSafeCompare } from "../random"
import { Storage } from "../storage/storage"
import { getRelativeUrl } from "../util"
import type { Provider } from "./provider"

/**
 * Password-based authentication provider for Draft Auth.
 * Supports user registration, login, and password changes with email verification.
 *
 * ## Quick Setup
 *
 * ```ts
 * import { PasswordUI } from "@draftauth/core/ui/password"
 * import { PasswordProvider } from "@draftauth/core/provider/password"
 *
 * export default issuer({
 *   providers: {
 *     password: PasswordProvider(
 *       PasswordUI({
 *         copy: {
 *           error_email_taken: "This email is already taken."
 *         },
 *         sendCode: async (email, code) => {
 *           await sendEmail(email, `Your verification code: ${code}`)
 *         }
 *       })
 *     )
 *   }
 * })
 * ```
 *
 * ## Custom UI Implementation
 *
 * For full control over the user interface, implement the handlers directly:
 *
 * ```ts
 * PasswordProvider({
 *   login: async (req, form, error) => {
 *     return new Response(renderLoginPage(form, error))
 *   },
 *   register: async (req, state, form, error) => {
 *     return new Response(renderRegisterPage(state, form, error))
 *   },
 *   change: async (req, state, form, error) => {
 *     return new Response(renderChangePage(state, form, error))
 *   },
 *   sendCode: async (email, code) => {
 *     await yourEmailService.send(email, code)
 *   }
 * })
 * ```
 *
 * ## Features
 *
 * - **Email verification**: Secure registration with email confirmation codes
 * - **Password hashing**: Built-in Scrypt and PBKDF2 support with secure defaults
 * - **Password validation**: Configurable password strength requirements
 * - **Password reset**: Secure password change flow with email verification
 * - **Session management**: Automatic invalidation on password changes
 *
 * @packageDocumentation
 */

/**
 * Password hashing interface for secure password storage.
 * Implement this interface to use custom password hashing algorithms.
 *
 * @template T - The hash storage format (usually an object with hash, salt, and params)
 * @internal
 */
export interface PasswordHasher<T> {
	/**
	 * Hashes a plaintext password for secure storage.
	 *
	 * @param password - The plaintext password to hash
	 * @returns Promise resolving to the hash data structure
	 */
	hash(password: string): Promise<T>

	/**
	 * Verifies a plaintext password against a stored hash.
	 *
	 * @param password - The plaintext password to verify
	 * @param compare - The stored hash data to compare against
	 * @returns Promise resolving to true if password matches
	 */
	verify(password: string, compare: T): Promise<boolean>
}

/**
 * Configuration for the password authentication provider.
 */
export interface PasswordConfig {
	/**
	 * Length of verification codes sent to users.
	 * @internal
	 * @default 6
	 */
	readonly length?: number

	/**
	 * Password hashing implementation to use.
	 * @internal
	 * @default ScryptHasher()
	 */
	readonly hasher?: PasswordHasher<unknown>

	/**
	 * Request handler for rendering the login screen.
	 * Receives the request, optional form data, and any login errors.
	 *
	 * @param req - The HTTP request object
	 * @param form - Form data from POST requests (if any)
	 * @param error - Login error to display (if any)
	 * @returns Promise resolving to the login page response
	 *
	 * @example
	 * ```ts
	 * login: async (req, form, error) => {
	 *   const html = renderLoginPage({
	 *     email: form?.get('email'),
	 *     error: error?.type
	 *   })
	 *   return new Response(html, {
	 *     headers: { 'Content-Type': 'text/html' }
	 *   })
	 * }
	 * ```
	 */
	login: (req: Request, form?: FormData, error?: PasswordLoginError) => Promise<Response>

	/**
	 * Request handler for rendering the registration screen.
	 * Handles both initial registration form and email verification.
	 *
	 * @param req - The HTTP request object
	 * @param state - Current registration state (start or code verification)
	 * @param form - Form data from POST requests (if any)
	 * @param error - Registration error to display (if any)
	 * @returns Promise resolving to the registration page response
	 *
	 * @example
	 * ```ts
	 * register: async (req, state, form, error) => {
	 *   if (state.type === 'start') {
	 *     return new Response(renderRegistrationForm(error))
	 *   } else {
	 *     return new Response(renderCodeVerification(state.email, error))
	 *   }
	 * }
	 * ```
	 */
	register: (
		req: Request,
		state: PasswordRegisterState,
		form?: FormData,
		error?: PasswordRegisterError
	) => Promise<Response>

	/**
	 * Request handler for rendering the password change screen.
	 * Handles email entry, code verification, and password update steps.
	 *
	 * @param req - The HTTP request object
	 * @param state - Current password change state
	 * @param form - Form data from POST requests (if any)
	 * @param error - Password change error to display (if any)
	 * @returns Promise resolving to the password change page response
	 *
	 * @example
	 * ```ts
	 * change: async (req, state, form, error) => {
	 *   switch (state.type) {
	 *     case 'start':
	 *       return new Response(renderEmailForm(error))
	 *     case 'code':
	 *       return new Response(renderCodeForm(state.email, error))
	 *     case 'update':
	 *       return new Response(renderPasswordForm(error))
	 *   }
	 * }
	 * ```
	 */
	change: (
		req: Request,
		state: PasswordChangeState,
		form?: FormData,
		error?: PasswordChangeError
	) => Promise<Response>

	/**
	 * Callback for sending verification codes to users via email.
	 * Implement this to integrate with your email service provider.
	 *
	 * @param email - The recipient's email address
	 * @param code - The verification code to send
	 * @returns Promise that resolves when email is sent
	 *
	 * @example
	 * ```ts
	 * sendCode: async (email, code) => {
	 *   await emailService.send({
	 *     to: email,
	 *     subject: 'Your verification code',
	 *     text: `Your verification code is: ${code}`
	 *   })
	 * }
	 * ```
	 */
	sendCode: (email: string, code: string) => Promise<void>

	/**
	 * Optional password validation function or schema.
	 * Can be either a validation function or a standard-schema validator.
	 *
	 * @param password - The password to validate
	 * @returns Error message if invalid, undefined if valid
	 *
	 * @example
	 * ```ts
	 * // Function-based validation
	 * validatePassword: (password) => {
	 *   if (password.length < 8) return "Password must be at least 8 characters"
	 *   if (!/[A-Z]/.test(password)) return "Password must contain uppercase letter"
	 *   return undefined
	 * }
	 *
	 * // Schema-based validation
	 * validatePassword: pipe(
	 *   string(),
	 *   minLength(8, "Password must be at least 8 characters"),
	 *   regex(/[A-Z]/, "Password must contain uppercase letter")
	 * )
	 * ```
	 */
	readonly validatePassword?:
		| StandardSchemaV1
		| ((password: string) => Promise<string | undefined> | string | undefined)
}

/**
 * Registration flow states that determine which UI to show.
 * The registration process moves through these states sequentially.
 */
export type PasswordRegisterState =
	| {
			/** Initial state: user enters email and password */
			readonly type: "start"
	  }
	| {
			/** Code verification state: user enters emailed verification code */
			readonly type: "code"
			/** The verification code sent to the user */
			readonly code: string
			/** The user's email address */
			readonly email: string
			/** The hashed password (ready for storage) */
			readonly password: unknown
	  }

/**
 * Possible errors during user registration.
 */
export type PasswordRegisterError =
	| {
			/** The verification code entered is incorrect */
			readonly type: "invalid_code"
	  }
	| {
			/** The email address is already registered */
			readonly type: "email_taken"
	  }
	| {
			/** The email address format is invalid */
			readonly type: "invalid_email"
	  }
	| {
			/** The password does not meet requirements */
			readonly type: "invalid_password"
	  }
	| {
			/** Password and confirmation password don't match */
			readonly type: "password_mismatch"
	  }
	| {
			/** Custom validation error from validatePassword callback */
			readonly type: "validation_error"
			readonly message?: string
	  }

/**
 * Password change flow states that determine which UI to show.
 */
export type PasswordChangeState =
	| {
			/** Initial state: user enters their email address */
			readonly type: "start"
			/** URL to redirect to after successful password change */
			readonly redirect: string
	  }
	| {
			/** Code verification state: user enters emailed verification code */
			readonly type: "code"
			/** The verification code sent to the user */
			readonly code: string
			/** The user's email address */
			readonly email: string
			/** URL to redirect to after completion */
			readonly redirect: string
	  }
	| {
			/** Password update state: user enters new password */
			readonly type: "update"
			/** URL to redirect to after completion */
			readonly redirect: string
			/** The verified email address */
			readonly email: string
	  }

/**
 * Possible errors during password changes.
 */
export type PasswordChangeError =
	| {
			/** The email address format is invalid */
			readonly type: "invalid_email"
	  }
	| {
			/** The verification code entered is incorrect */
			readonly type: "invalid_code"
	  }
	| {
			/** The new password does not meet requirements */
			readonly type: "invalid_password"
	  }
	| {
			/** New password and confirmation don't match */
			readonly type: "password_mismatch"
	  }
	| {
			/** Custom validation error from validatePassword callback */
			readonly type: "validation_error"
			readonly message: string
	  }

/**
 * Possible errors during login attempts.
 */
export type PasswordLoginError =
	| {
			/** The email address format is invalid */
			readonly type: "invalid_email"
	  }
	| {
			/** The password is incorrect or email not found */
			readonly type: "invalid_password"
	  }

/**
 * User data returned by successful password authentication.
 */
export interface PasswordUserData {
	/** The authenticated user's email address */
	readonly email: string
}

/**
 * Creates a password authentication provider with email verification.
 * Implements secure registration, login, and password change flows.
 *
 * @param config - Provider configuration including UI handlers and email service
 * @returns Provider instance implementing password authentication
 *
 * @example
 * ```ts
 * const provider = PasswordProvider({
 *   login: async (req, form, error) => {
 *     return new Response(renderLogin(form, error))
 *   },
 *   register: async (req, state, form, error) => {
 *     return new Response(renderRegister(state, form, error))
 *   },
 *   change: async (req, state, form, error) => {
 *     return new Response(renderChange(state, form, error))
 *   },
 *   sendCode: async (email, code) => {
 *     await emailService.send(email, `Code: ${code}`)
 *   },
 *   validatePassword: (pwd) => {
 *     return pwd.length >= 8 ? undefined : "Too short"
 *   }
 * })
 * ```
 */
export const PasswordProvider = (config: PasswordConfig): Provider<PasswordUserData> => {
	const hasher = config.hasher ?? ScryptHasher()

	/**
	 * Generates a cryptographically secure verification code.
	 */
	const generateCode = (): string => {
		return generateUnbiasedDigits(config.length ?? 6)
	}

	return {
		type: "password",

		init(routes, ctx) {
			/**
			 * GET /authorize - Display login form
			 */
			routes.get("/authorize", async (c) => ctx.forward(c, await config.login(c.req.raw)))

			/**
			 * POST /authorize - Process login attempt
			 */
			routes.post("/authorize", async (c) => {
				const formData = await c.req.formData()

				const error = async (err: PasswordLoginError): Promise<Response> => {
					return ctx.forward(c, await config.login(c.req.raw, formData, err))
				}

				const email = formData.get("email")?.toString()?.toLowerCase()
				if (!email) return error({ type: "invalid_email" })

				const storedHash = await Storage.get<unknown>(ctx.storage, [
					"email",
					email,
					"password"
				])
				const password = formData.get("password")?.toString()

				if (!password || !storedHash || !(await hasher.verify(password, storedHash))) {
					return error({ type: "invalid_password" })
				}

				return ctx.success(
					c,
					{ email },
					{
						invalidate: async (subject) => {
							await Storage.set(ctx.storage, ["email", email, "subject"], subject)
						}
					}
				)
			})

			/**
			 * GET /register - Display registration form
			 */
			routes.get("/register", async (c) => {
				const state: PasswordRegisterState = { type: "start" }
				await ctx.set(c, "provider", 60 * 60 * 24, state)
				return ctx.forward(c, await config.register(c.req.raw, state))
			})

			/**
			 * POST /register - Process registration steps
			 */
			routes.post("/register", async (c) => {
				const formData = await c.req.formData()
				const email = formData.get("email")?.toString()?.toLowerCase()
				const action = formData.get("action")?.toString()
				const provider = await ctx.get<PasswordRegisterState>(c, "provider")

				if (!provider) {
					const state: PasswordRegisterState = { type: "start" }
					await ctx.set(c, "provider", 60 * 60 * 24, state)
					return ctx.forward(c, await config.register(c.req.raw, state))
				}

				const transition = async (
					next: PasswordRegisterState,
					err?: PasswordRegisterError
				): Promise<Response> => {
					await ctx.set<PasswordRegisterState>(c, "provider", 60 * 60 * 24, next)
					return ctx.forward(c, await config.register(c.req.raw, next, formData, err))
				}

				if (action === "register" && provider.type === "start") {
					const password = formData.get("password")?.toString()
					const repeat = formData.get("repeat")?.toString()

					if (!email) return transition(provider, { type: "invalid_email" })
					if (!password) return transition(provider, { type: "invalid_password" })
					if (password !== repeat) return transition(provider, { type: "password_mismatch" })

					// Validate password if validator is configured
					if (config.validatePassword) {
						let validationError: string | undefined
						try {
							if (typeof config.validatePassword === "function") {
								validationError = await config.validatePassword(password)
							} else {
								const result = await config.validatePassword["~standard"].validate(password)
								if (result.issues?.length) {
									throw new Error(result.issues.map((issue) => issue.message).join(", "))
								}
							}
						} catch (error) {
							validationError = error instanceof Error ? error.message : undefined
						}
						if (validationError) {
							return transition(provider, {
								type: "validation_error",
								message: validationError
							})
						}
					}

					// Check if email is already taken
					const existingUser = await Storage.get(ctx.storage, ["email", email, "password"])
					if (existingUser) return transition(provider, { type: "email_taken" })

					// Generate verification code and send email
					const code = generateCode()
					await config.sendCode(email, code)

					return transition({
						type: "code",
						code,
						password: await hasher.hash(password),
						email
					})
				}

				if (action === "register" && provider.type === "code") {
					// Resend verification code
					const code = generateCode()
					await config.sendCode(provider.email, code)
					return transition({
						type: "code",
						code,
						password: provider.password,
						email: provider.email
					})
				}

				if (action === "verify" && provider.type === "code") {
					const code = formData.get("code")?.toString()
					if (!code || !timingSafeCompare(code, provider.code)) {
						return transition(provider, { type: "invalid_code" })
					}

					// Double-check email hasn't been taken since code was sent
					const existingUser = await Storage.get(ctx.storage, [
						"email",
						provider.email,
						"password"
					])
					if (existingUser) return transition({ type: "start" }, { type: "email_taken" })

					// Store password and complete registration
					await Storage.set(
						ctx.storage,
						["email", provider.email, "password"],
						provider.password
					)

					return ctx.success(c, { email: provider.email })
				}

				return transition({ type: "start" })
			})

			/**
			 * GET /change - Display password change form
			 */
			routes.get("/change", async (c) => {
				const redirect = c.req.query("redirect_uri") || getRelativeUrl(c, "./authorize")
				const state: PasswordChangeState = {
					type: "start",
					redirect
				}
				await ctx.set(c, "provider", 60 * 60 * 24, state)
				return ctx.forward(c, await config.change(c.req.raw, state))
			})

			/**
			 * POST /change - Process password change steps
			 */
			routes.post("/change", async (c) => {
				const formData = await c.req.formData()
				const action = formData.get("action")?.toString()
				const provider = await ctx.get<PasswordChangeState>(c, "provider")

				if (!provider) throw new UnknownStateError()

				const transition = async (
					next: PasswordChangeState,
					err?: PasswordChangeError
				): Promise<Response> => {
					await ctx.set<PasswordChangeState>(c, "provider", 60 * 60 * 24, next)
					return ctx.forward(c, await config.change(c.req.raw, next, formData, err))
				}

				if (action === "code") {
					const email = formData.get("email")?.toString()?.toLowerCase()
					if (!email) {
						return transition(
							{ type: "start", redirect: provider.redirect },
							{ type: "invalid_email" }
						)
					}

					const code = generateCode()
					await config.sendCode(email, code)

					return transition({
						type: "code",
						code,
						email,
						redirect: provider.redirect
					})
				}

				if (action === "verify" && provider.type === "code") {
					const code = formData.get("code")?.toString()
					if (!code || !timingSafeCompare(code, provider.code)) {
						return transition(provider, { type: "invalid_code" })
					}

					return transition({
						type: "update",
						email: provider.email,
						redirect: provider.redirect
					})
				}

				if (action === "update" && provider.type === "update") {
					const existingPassword = await Storage.get(ctx.storage, [
						"email",
						provider.email,
						"password"
					])
					if (!existingPassword) return c.redirect(provider.redirect, 302)

					const password = formData.get("password")?.toString()
					const repeat = formData.get("repeat")?.toString()

					if (!password) return transition(provider, { type: "invalid_password" })
					if (password !== repeat) return transition(provider, { type: "password_mismatch" })

					// Validate new password
					if (config.validatePassword) {
						let validationError: string | undefined
						try {
							if (typeof config.validatePassword === "function") {
								validationError = await config.validatePassword(password)
							} else {
								const result = await config.validatePassword["~standard"].validate(password)
								if (result.issues?.length) {
									throw new Error(result.issues.map((issue) => issue.message).join(", "))
								}
							}
						} catch (error) {
							validationError = error instanceof Error ? error.message : undefined
						}
						if (validationError) {
							return transition(provider, {
								type: "validation_error",
								message: validationError
							})
						}
					}

					// Update password and invalidate existing sessions
					await Storage.set(
						ctx.storage,
						["email", provider.email, "password"],
						await hasher.hash(password)
					)

					const subject = await Storage.get<string>(ctx.storage, [
						"email",
						provider.email,
						"subject"
					])
					if (subject) await ctx.invalidate(subject)

					return c.redirect(provider.redirect, 302)
				}

				return transition({ type: "start", redirect: provider.redirect })
			})
		}
	}
}

// ========================================
// Password Hashing Implementations
// ========================================

import * as jose from "jose"
import { TextEncoder } from "node:util"

/**
 * PBKDF2 password hasher with configurable iterations.
 * Good choice for compatibility but slower than Scrypt.
 *
 * @param opts - Configuration options
 * @returns Password hasher using PBKDF2 algorithm
 * @internal
 */
export const PBKDF2Hasher = (opts?: {
	iterations?: number
}): PasswordHasher<{
	hash: string
	salt: string
	iterations: number
}> => {
	const iterations = opts?.iterations ?? 600000

	return {
		async hash(password: string) {
			const encoder = new TextEncoder()
			const passwordBytes = encoder.encode(password)
			const salt = crypto.getRandomValues(new Uint8Array(16))

			const keyMaterial = await crypto.subtle.importKey(
				"raw",
				passwordBytes,
				"PBKDF2",
				false,
				["deriveBits"]
			)

			const hashBuffer = await crypto.subtle.deriveBits(
				{
					name: "PBKDF2",
					hash: "SHA-256",
					salt: salt,
					iterations
				},
				keyMaterial,
				256
			)

			const hashBase64 = jose.base64url.encode(new Uint8Array(hashBuffer))
			const saltBase64 = jose.base64url.encode(salt)

			return {
				hash: hashBase64,
				salt: saltBase64,
				iterations
			}
		},

		async verify(password: string, compare) {
			const encoder = new TextEncoder()
			const passwordBytes = encoder.encode(password)
			const salt = jose.base64url.decode(compare.salt)

			const keyMaterial = await crypto.subtle.importKey(
				"raw",
				passwordBytes,
				"PBKDF2",
				false,
				["deriveBits"]
			)

			const hashBuffer = await crypto.subtle.deriveBits(
				{
					name: "PBKDF2",
					hash: "SHA-256",
					salt,
					iterations: compare.iterations
				},
				keyMaterial,
				256
			)

			const hashBase64 = jose.base64url.encode(new Uint8Array(hashBuffer))
			return timingSafeCompare(hashBase64, compare.hash)
		}
	}
}

import { randomBytes, scrypt, timingSafeEqual } from "node:crypto"

/**
 * Scrypt password hasher with secure defaults.
 * Recommended choice for new applications due to memory-hard properties.
 *
 * @param opts - Scrypt parameters (N, r, p)
 * @returns Password hasher using Scrypt algorithm
 * @internal
 */
export const ScryptHasher = (opts?: {
	N?: number
	r?: number
	p?: number
}): PasswordHasher<{
	hash: string
	salt: string
	N: number
	r: number
	p: number
}> => {
	const N = opts?.N ?? 16384 // CPU/memory cost factor
	const r = opts?.r ?? 8 // Block size
	const p = opts?.p ?? 1 // Parallelization factor

	return {
		async hash(password: string) {
			const salt = randomBytes(16)
			const keyLength = 32 // 256 bits

			const derivedKey = await new Promise<Buffer>((resolve, reject) => {
				scrypt(password, salt, keyLength, { N, r, p }, (err, derivedKey) => {
					if (err) reject(err)
					else resolve(derivedKey)
				})
			})

			const hashBase64 = derivedKey.toString("base64")
			const saltBase64 = salt.toString("base64")

			return {
				hash: hashBase64,
				salt: saltBase64,
				N,
				r,
				p
			}
		},

		async verify(password: string, compare) {
			const salt = Buffer.from(compare.salt, "base64")
			const keyLength = 32 // 256 bits

			const derivedKey = await new Promise<Buffer>((resolve, reject) => {
				scrypt(
					password,
					salt,
					keyLength,
					{ N: compare.N, r: compare.r, p: compare.p },
					(err, derivedKey) => {
						if (err) reject(err)
						else resolve(derivedKey)
					}
				)
			})

			return timingSafeEqual(derivedKey, Buffer.from(compare.hash, "base64"))
		}
	}
}
