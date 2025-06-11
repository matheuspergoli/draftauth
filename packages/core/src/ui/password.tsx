/**
 * Pre-built UI component for password-based authentication flows.
 * Provides complete interfaces for login, registration, and password changes with email verification.
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
 *         sendCode: async (email, code) => {
 *           await emailService.send(email, `Your verification code: ${code}`)
 *         }
 *       })
 *     )
 *   }
 * })
 * ```
 *
 * ## Customization
 *
 * ```ts
 * const customPasswordUI = PasswordUI({
 *   copy: {
 *     login_title: "Welcome Back",
 *     register_title: "Join Our Platform",
 *     error_email_taken: "This email is already registered",
 *     error_invalid_password: "Please check your password"
 *   },
 *   validatePassword: (password) => {
 *     if (password.length < 8) return "Password must be at least 8 characters"
 *     if (!/[A-Z]/.test(password)) return "Password must contain uppercase letter"
 *     return undefined
 *   },
 *   sendCode: async (email, code) => {
 *     await emailService.send({
 *       to: email,
 *       subject: 'Password Reset Code',
 *       template: 'verification-code',
 *       data: { code, expiresIn: '10 minutes' }
 *     })
 *   }
 * })
 * ```
 *
 * ## Features
 *
 * - **Complete Auth Flow**: Login, registration, and password reset
 * - **Email Verification**: Built-in email verification with PIN codes
 * - **Form Validation**: Real-time validation with clear error messages
 * - **Responsive Design**: Works on all device sizes
 * - **Accessibility**: ARIA labels, proper input types, and keyboard navigation
 * - **Custom Copy**: Fully customizable text and error messages
 * - **Auto-focus**: Smart focus management for better UX
 *
 * @packageDocumentation
 */

/** @jsxImportSource hono/jsx */

import type {
	PasswordChangeError,
	PasswordConfig,
	PasswordLoginError,
	PasswordRegisterError
} from "../provider/password"
import { Layout } from "./base"
import { FormAlert } from "./form"

/**
 * Default text copy for all password authentication UI screens.
 * All text can be customized via the copy prop.
 */
const DEFAULT_COPY = {
	// Error messages
	/** Error message when email is already taken during registration */
	error_email_taken: "There is already an account with this email.",
	/** Error message when the verification code is incorrect */
	error_invalid_code: "Code is incorrect.",
	/** Error message when the email format is invalid */
	error_invalid_email: "Email is not valid.",
	/** Error message when the password is incorrect during login */
	error_invalid_password: "Password is incorrect.",
	/** Error message when password confirmation doesn't match */
	error_password_mismatch: "Passwords do not match.",
	/** Error message when password fails custom validation */
	error_validation_error: "Password does not meet requirements.",

	// Page titles and descriptions
	/** Title displayed on the registration page */
	register_title: "Welcome to the app",
	/** Description text on the registration page */
	register_description: "Sign in with your email",
	/** Title displayed on the login page */
	login_title: "Welcome to the app",
	/** Description text on the login page */
	login_description: "Sign in with your email",

	// Action buttons and links
	/** Text for the registration button */
	register: "Register",
	/** Prompt text before the registration link */
	register_prompt: "Don't have an account?",
	/** Prompt text before the login link */
	login_prompt: "Already have an account?",
	/** Text for the login button */
	login: "Login",
	/** Text for the forgot password link */
	change_prompt: "Forgot password?",
	/** Text for the resend verification code button */
	code_resend: "Resend code",
	/** Text for the "back to login" link */
	code_return: "Back to",

	// Input placeholders
	/** Placeholder text for email input fields */
	input_email: "Email",
	/** Placeholder text for password input fields */
	input_password: "Password",
	/** Placeholder text for verification code input */
	input_code: "Code",
	/** Placeholder text for password confirmation input */
	input_repeat: "Repeat password",

	// Generic action button
	/** Text for primary action buttons */
	button_continue: "Continue",

	// Internal
	/** Logo text (internal use) */
	logo: "A"
}

/**
 * Type for customizable UI copy text.
 * All properties are optional to allow partial customization.
 */
type PasswordUICopy = typeof DEFAULT_COPY

/**
 * Configuration options for the PasswordUI component.
 */
export interface PasswordUIOptions
	extends Pick<PasswordConfig, "sendCode" | "validatePassword"> {
	/**
	 * Custom text copy for UI labels, messages, and errors.
	 * Allows full customization of all displayed text.
	 *
	 * @example
	 * ```ts
	 * copy: {
	 *   login_title: "Welcome Back!",
	 *   register_title: "Join Our Community",
	 *   error_invalid_password: "Hmm, that password doesn't look right",
	 *   button_continue: "Let's Go!"
	 * }
	 * ```
	 */
	readonly copy?: Partial<PasswordUICopy>
}

/**
 * Creates a complete UI configuration for password-based authentication.
 * Provides pre-built forms for login, registration, and password changes.
 *
 * @param options - Configuration options for the UI
 * @returns Complete PasswordProvider configuration with UI handlers
 *
 * @example
 * ```ts
 * // Basic password authentication
 * const basicPasswordUI = PasswordUI({
 *   sendCode: async (email, code) => {
 *     await emailService.send(email, `Verification code: ${code}`)
 *   }
 * })
 *
 * // Advanced setup with validation and custom copy
 * const advancedPasswordUI = PasswordUI({
 *   copy: {
 *     login_title: "Welcome Back",
 *     register_title: "Create Your Account",
 *     error_email_taken: "This email is already registered with us",
 *     input_password: "Choose a strong password"
 *   },
 *   validatePassword: (password) => {
 *     if (password.length < 8) return "Password must be at least 8 characters"
 *     if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(password)) {
 *       return "Password must contain uppercase, lowercase, and number"
 *     }
 *     return undefined
 *   },
 *   sendCode: async (email, code) => {
 *     await emailService.send({
 *       to: email,
 *       subject: 'Your verification code',
 *       html: `
 *         <h2>Verification Code</h2>
 *         <p>Your verification code is: <strong>${code}</strong></p>
 *         <p>This code expires in 10 minutes.</p>
 *       `
 *     })
 *   }
 * })
 * ```
 */
export const PasswordUI = (options: PasswordUIOptions): PasswordConfig => {
	const copy = {
		...DEFAULT_COPY,
		...options.copy
	}

	/**
	 * Gets the appropriate error message for display.
	 * Handles special case for validation errors with custom messages.
	 */
	const getErrorMessage = (
		error: PasswordLoginError | PasswordRegisterError | PasswordChangeError | undefined
	): string | undefined => {
		if (!error?.type) return undefined

		if (error.type === "validation_error" && "message" in error && error.message) {
			return error.message
		}

		return copy[`error_${error.type}` as keyof typeof copy]
	}

	return {
		validatePassword: options.validatePassword,
		sendCode: options.sendCode,

		/**
		 * Renders the login form with email and password inputs.
		 */
		login: async (_req, form, error): Promise<Response> => {
			const jsx = (
				<Layout>
					<form data-component="form" method="post">
						<FormAlert message={getErrorMessage(error)} />

						<input
							data-component="input"
							type="email"
							name="email"
							required
							placeholder={copy.input_email}
							defaultValue={form?.get("email")?.toString()}
							autoComplete="email"
						/>

						<input
							data-component="input"
							type="password"
							name="password"
							required
							placeholder={copy.input_password}
							autoComplete="current-password"
						/>

						<button type="submit" data-component="button">
							{copy.button_continue}
						</button>

						<div data-component="form-footer">
							<span>
								{copy.register_prompt}{" "}
								<a data-component="link" href="register">
									{copy.register}
								</a>
							</span>
							<a data-component="link" href="change">
								{copy.change_prompt}
							</a>
						</div>
					</form>
				</Layout>
			)

			return new Response(jsx.toString(), {
				status: error ? 401 : 200,
				headers: { "Content-Type": "text/html" }
			})
		},

		/**
		 * Renders the registration form with email verification flow.
		 * Handles both initial registration and email verification steps.
		 */
		register: async (_req, state, form, error): Promise<Response> => {
			const emailError = ["invalid_email", "email_taken"].includes(error?.type || "")
			const passwordError = [
				"invalid_password",
				"password_mismatch",
				"validation_error"
			].includes(error?.type || "")

			const jsx = (
				<Layout>
					<form data-component="form" method="post">
						<FormAlert message={getErrorMessage(error)} />

						{state.type === "start" && (
							<>
								<input type="hidden" name="action" value="register" />

								<input
									data-component="input"
									type="email"
									name="email"
									required
									placeholder={copy.input_email}
									defaultValue={!emailError ? form?.get("email")?.toString() : ""}
									autoComplete="email"
								/>

								<input
									data-component="input"
									type="password"
									name="password"
									required
									placeholder={copy.input_password}
									defaultValue={!passwordError ? form?.get("password")?.toString() : ""}
									autoComplete="new-password"
								/>

								<input
									data-component="input"
									type="password"
									name="repeat"
									required
									placeholder={copy.input_repeat}
									autoComplete="new-password"
								/>

								<button type="submit" data-component="button">
									{copy.button_continue}
								</button>

								<div data-component="form-footer">
									<span>
										{copy.login_prompt}{" "}
										<a data-component="link" href="authorize">
											{copy.login}
										</a>
									</span>
								</div>
							</>
						)}

						{state.type === "code" && (
							<>
								<input type="hidden" name="action" value="verify" />

								<input
									data-component="input"
									type="text"
									name="code"
									required
									placeholder={copy.input_code}
									minLength={6}
									maxLength={6}
									inputMode="numeric"
									autoComplete="one-time-code"
									pattern="[0-9]{6}"
									aria-label="6-digit verification code"
								/>

								<button type="submit" data-component="button">
									{copy.button_continue}
								</button>
							</>
						)}
					</form>
				</Layout>
			)

			return new Response(jsx.toString(), {
				headers: { "Content-Type": "text/html" }
			})
		},

		/**
		 * Renders the password change form with email verification.
		 * Handles email entry, code verification, and password update steps.
		 */
		change: async (_req, state, form, error): Promise<Response> => {
			const passwordError = [
				"invalid_password",
				"password_mismatch",
				"validation_error"
			].includes(error?.type || "")

			const jsx = (
				<Layout>
					<form data-component="form" method="post">
						<FormAlert message={getErrorMessage(error)} />

						{state.type === "start" && (
							<>
								<input type="hidden" name="action" value="code" />

								<input
									data-component="input"
									type="email"
									name="email"
									required
									placeholder={copy.input_email}
									defaultValue={form?.get("email")?.toString()}
									autoComplete="email"
								/>
							</>
						)}

						{state.type === "code" && (
							<>
								<input type="hidden" name="action" value="verify" />

								<input
									data-component="input"
									type="text"
									name="code"
									required
									placeholder={copy.input_code}
									minLength={6}
									maxLength={6}
									inputMode="numeric"
									autoComplete="one-time-code"
									pattern="[0-9]{6}"
									aria-label="6-digit verification code"
								/>
							</>
						)}

						{state.type === "update" && (
							<>
								<input type="hidden" name="action" value="update" />

								<input
									data-component="input"
									type="password"
									name="password"
									required
									placeholder={copy.input_password}
									defaultValue={!passwordError ? form?.get("password")?.toString() : ""}
									autoComplete="new-password"
								/>

								<input
									data-component="input"
									type="password"
									name="repeat"
									required
									placeholder={copy.input_repeat}
									defaultValue={!passwordError ? form?.get("repeat")?.toString() : ""}
									autoComplete="new-password"
								/>
							</>
						)}

						<button type="submit" data-component="button">
							{copy.button_continue}
						</button>
					</form>

					{/* Resend code form for verification step */}
					{state.type === "code" && (
						<form method="post">
							<input type="hidden" name="action" value="code" />
							<input type="hidden" name="email" value={state.email} />

							<div data-component="form-footer">
								<span>
									{copy.code_return}{" "}
									<a data-component="link" href="authorize">
										{copy.login.toLowerCase()}
									</a>
								</span>
								<button type="submit" data-component="link">
									{copy.code_resend}
								</button>
							</div>
						</form>
					)}
				</Layout>
			)

			return new Response(jsx.toString(), {
				status: error ? 400 : 200,
				headers: { "Content-Type": "text/html" }
			})
		}
	}
}
