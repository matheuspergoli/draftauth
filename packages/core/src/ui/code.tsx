/**
 * Pre-built UI component for PIN code authentication flow.
 * Provides a complete interface for collecting user claims and verifying PIN codes.
 *
 * ## Quick Setup
 *
 * ```ts
 * import { CodeUI } from "@draftauth/core/ui/code"
 * import { CodeProvider } from "@draftauth/core/provider/code"
 *
 * export default issuer({
 *   providers: {
 *     email: CodeProvider(
 *       CodeUI({
 *         sendCode: async (claims, code) => {
 *           await emailService.send(claims.email, `Your code: ${code}`)
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
 * const customCodeUI = CodeUI({
 *   mode: "phone", // Switch to phone number input
 *   copy: {
 *     email_placeholder: "Enter your phone number",
 *     code_info: "We'll send a verification code via SMS",
 *     button_continue: "Send Code"
 *   },
 *   sendCode: async (claims, code) => {
 *     if (claims.phone) {
 *       await smsService.send(claims.phone, `Verification code: ${code}`)
 *     } else {
 *       return { type: "invalid_claim", key: "phone", value: "Phone number required" }
 *     }
 *   }
 * })
 * ```
 *
 * ## Features
 *
 * - **Email/Phone Mode**: Switch between email and phone number collection
 * - **Custom Copy**: Fully customizable text and messaging
 * - **Responsive Design**: Works on all device sizes
 * - **Accessibility**: ARIA labels, proper input types, and keyboard navigation
 * - **Error Handling**: Clear error states for invalid codes and claims
 * - **Resend Functionality**: Built-in code resend capability
 *
 * @packageDocumentation
 */

/** @jsxImportSource hono/jsx */

import { UnknownStateError } from "../error"
import type { CodeProviderError, CodeProviderOptions } from "../provider/code"
import { Layout } from "./base"
import { FormAlert } from "./form"

/**
 * Default text copy for the PIN code authentication UI.
 * All text can be customized via the copy prop.
 */
const DEFAULT_COPY = {
	/** Placeholder text for the email/contact input field */
	email_placeholder: "Email",
	/** Error message displayed when the entered email/contact is invalid */
	email_invalid: "Email address is not valid",
	/** Text for the primary action button */
	button_continue: "Continue",
	/** Informational text explaining that a PIN code will be sent */
	code_info: "We'll send a pin code to your email.",
	/** Placeholder text for the PIN code input field */
	code_placeholder: "Code",
	/** Error message displayed when the entered PIN code is incorrect */
	code_invalid: "Invalid code",
	/** Success message prefix when code is initially sent */
	code_sent: "Code sent to ",
	/** Success message prefix when code is resent */
	code_resent: "Code resent to ",
	/** Text asking if user didn't receive the code */
	code_didnt_get: "Didn't get code?",
	/** Text for the resend code button */
	code_resend: "Resend"
}

/**
 * Type for customizable UI copy text.
 * All properties are optional to allow partial customization.
 */
export type CodeUICopy = typeof DEFAULT_COPY

/**
 * Input mode for the contact field.
 * Determines the input type and validation behavior.
 */
export type CodeUIMode = "email" | "phone"

/**
 * Configuration options for the CodeUI component.
 */
export interface CodeUIOptions {
	/**
	 * Callback function for sending PIN codes to users.
	 * Should handle delivery via email, SMS, or other channels based on the claims.
	 *
	 * @param claims - User contact information (email, phone, etc.)
	 * @param code - The generated PIN code to send
	 * @returns Promise resolving to undefined on success, or error object on failure
	 *
	 * @example
	 * ```ts
	 * sendCode: async (claims, code) => {
	 *   if (claims.email) {
	 *     await emailService.send({
	 *       to: claims.email,
	 *       subject: 'Your verification code',
	 *       text: `Your PIN code is: ${code}`
	 *     })
	 *   } else if (claims.phone) {
	 *     await smsService.send(claims.phone, `PIN: ${code}`)
	 *   } else {
	 *     return {
	 *       type: "invalid_claim",
	 *       key: "contact",
	 *       value: "Email or phone required"
	 *     }
	 *   }
	 * }
	 * ```
	 */
	sendCode: (
		claims: Record<string, string>,
		code: string
	) => Promise<CodeProviderError | undefined>

	/**
	 * Custom text copy for UI labels and messages.
	 * Allows full customization of all displayed text.
	 *
	 * @example
	 * ```ts
	 * copy: {
	 *   email_placeholder: "Enter your email address",
	 *   code_info: "Check your email for a 6-digit verification code",
	 *   button_continue: "Verify",
	 *   code_invalid: "The code you entered is incorrect"
	 * }
	 * ```
	 */
	readonly copy?: Partial<CodeUICopy>

	/**
	 * Input mode determining the type of contact information to collect.
	 *
	 * @default "email"
	 *
	 * @example
	 * ```ts
	 * mode: "phone" // Collect phone numbers instead of emails
	 * ```
	 */
	readonly mode?: CodeUIMode
}

/**
 * Creates a complete UI configuration for PIN code authentication.
 * Provides pre-built forms for collecting user contact info and verifying PIN codes.
 *
 * @param options - Configuration options for the UI
 * @returns Complete CodeProvider configuration with UI handlers
 *
 * @example
 * ```ts
 * // Basic email-based PIN authentication
 * const emailCodeUI = CodeUI({
 *   sendCode: async (claims, code) => {
 *     await emailService.send(claims.email, `Code: ${code}`)
 *   }
 * })
 *
 * // Phone-based PIN authentication with custom copy
 * const phoneCodeUI = CodeUI({
 *   mode: "phone",
 *   copy: {
 *     email_placeholder: "Phone number",
 *     code_info: "We'll send a verification code via SMS",
 *     email_invalid: "Please enter a valid phone number"
 *   },
 *   sendCode: async (claims, code) => {
 *     await smsService.send(claims.phone, `Verification: ${code}`)
 *   }
 * })
 *
 * // Multi-mode authentication
 * const flexibleCodeUI = CodeUI({
 *   copy: {
 *     email_placeholder: "Email or phone number",
 *     code_info: "We'll send a code to your email or phone"
 *   },
 *   sendCode: async (claims, code) => {
 *     if (claims.email && claims.email.includes('@')) {
 *       await emailService.send(claims.email, `Code: ${code}`)
 *     } else if (claims.email) {
 *       // Treat as phone number if no @ symbol
 *       await smsService.send(claims.email, `Code: ${code}`)
 *     } else {
 *       return {
 *         type: "invalid_claim",
 *         key: "contact",
 *         value: "Email or phone required"
 *       }
 *     }
 *   }
 * })
 * ```
 */
export const CodeUI = (options: CodeUIOptions): CodeProviderOptions => {
	const copy = {
		...DEFAULT_COPY,
		...options.copy
	}

	const inputMode = options.mode ?? "email"

	/**
	 * Determines the appropriate input field attributes based on the selected mode.
	 */
	const getInputAttributes = () => {
		switch (inputMode) {
			case "email":
				return {
					type: "email" as const,
					name: "email",
					inputmode: "email" as const,
					autocomplete: "email" as const
				}
			case "phone":
				return {
					type: "tel" as const,
					name: "phone",
					inputmode: "tel" as const,
					autocomplete: "tel" as const
				}
		}
	}

	/**
	 * Gets the appropriate contact value from claims for display purposes.
	 */
	const getContactValue = (claims: Record<string, string>): string => {
		return claims.email || claims.phone || Object.values(claims)[0] || ""
	}

	return {
		sendCode: options.sendCode,
		length: 6,

		request: async (_req, state, _form, error): Promise<Response> => {
			// Render contact information collection form
			if (state.type === "start") {
				const inputAttrs = getInputAttributes()

				const jsx = (
					<Layout>
						<form data-component="form" method="post">
							{/* Display validation error if present */}
							{error?.type === "invalid_claim" && <FormAlert message={copy.email_invalid} />}

							{/* Form action identifier */}
							<input name="action" type="hidden" value="request" />

							{/* Contact input field */}
							<input
								autofocus
								data-component="input"
								placeholder={copy.email_placeholder}
								required
								{...inputAttrs}
							/>

							{/* Submit button */}
							<button data-component="button" type="submit">
								{copy.button_continue}
							</button>
						</form>

						{/* Informational text */}
						<p data-component="form-footer">{copy.code_info}</p>
					</Layout>
				)

				return new Response(jsx.toString(), {
					headers: { "Content-Type": "text/html" }
				})
			}

			// Render PIN code verification form
			if (state.type === "code") {
				const contactValue = getContactValue(state.claims)

				const jsx = (
					<Layout>
						{/* Main verification form */}
						<form data-component="form" method="post">
							{/* Display code error if present */}
							{error?.type === "invalid_code" && <FormAlert message={copy.code_invalid} />}

							{/* Display success message */}
							<FormAlert
								color="success"
								message={(state.resend ? copy.code_resent : copy.code_sent) + contactValue}
							/>

							{/* Form action identifier */}
							<input name="action" type="hidden" value="verify" />

							{/* PIN code input */}
							<input
								aria-label="6-digit verification code"
								autocomplete="one-time-code"
								autofocus
								data-component="input"
								inputmode="numeric"
								maxLength={6}
								minLength={6}
								name="code"
								pattern="[0-9]{6}"
								placeholder={copy.code_placeholder}
								required
								type="text"
							/>

							{/* Verify button */}
							<button data-component="button" type="submit">
								{copy.button_continue}
							</button>
						</form>

						{/* Resend code form */}
						<form method="post">
							{/* Preserve claims as hidden inputs */}
							{Object.entries(state.claims).map(([key, value]) => (
								<input key={key} name={key} type="hidden" value={value} />
							))}

							{/* Resend action identifier */}
							<input name="action" type="hidden" value="resend" />

							{/* Resend link */}
							<div data-component="form-footer">
								<span>
									{copy.code_didnt_get}{" "}
									<button data-component="link" type="submit">
										{copy.code_resend}
									</button>
								</span>
							</div>
						</form>
					</Layout>
				)

				return new Response(jsx.toString(), {
					headers: { "Content-Type": "text/html" }
				})
			}

			throw new UnknownStateError()
		}
	}
}
