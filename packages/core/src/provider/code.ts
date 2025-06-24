/**
 * PIN code authentication provider for Draft Auth.
 * Supports flexible claim-based authentication via email, phone, or custom identifiers.
 *
 * ## Quick Setup
 *
 * ```ts
 * import { CodeUI } from "@draftauth/core/ui/code"
 * import { CodeProvider } from "@draftauth/core/provider/code"
 *
 * export default issuer({
 *   providers: {
 *     code: CodeProvider(
 *       CodeUI({
 *         copy: {
 *           code_info: "We'll send a PIN code to your email"
 *         },
 *         sendCode: async (claims, code) => {
 *           await sendEmail(claims.email, `Your code: ${code}`)
 *         }
 *       })
 *     )
 *   }
 * })
 * ```
 *
 * ## Custom Configuration
 *
 * ```ts
 * const customCodeProvider = CodeProvider({
 *   length: 4, // 4-digit PIN instead of default 6
 *   request: async (req, state, form, error) => {
 *     return new Response(renderCodePage(state, form, error))
 *   },
 *   sendCode: async (claims, code) => {
 *     if (claims.email) {
 *       await emailService.send(claims.email, code)
 *     } else if (claims.phone) {
 *       await smsService.send(claims.phone, code)
 *     } else {
 *       return { type: "invalid_claim", key: "contact", value: "missing" }
 *     }
 *   }
 * })
 * ```
 *
 * ## Features
 *
 * - **Flexible claims**: Support any claim type (email, phone, username, etc.)
 * - **Configurable PIN length**: 4-6 digit codes typically
 * - **Resend functionality**: Built-in code resend capability
 * - **Custom UI**: Full control over the authentication interface
 * - **Error handling**: Comprehensive error states for different failure modes
 *
 * ## Flow States
 *
 * The provider manages a two-step authentication flow:
 *
 * 1. **Start**: User enters their claim (email, phone, etc.)
 * 2. **Code**: User enters the PIN code sent to their claim
 *
 * ## User Data
 *
 * ```ts
 * success: async (ctx, value) => {
 *   if (value.provider === "code") {
 *     // User's email: value.claims.email
 *     // User's phone (if provided): value.claims.phone
 *     // Any other claims collected during the flow
 *   }
 * }
 * ```
 *
 * @packageDocumentation
 */

import type { Context } from "hono"
import { generateUnbiasedDigits, timingSafeCompare } from "../random"
import type { Provider } from "./provider"

/**
 * Configuration options for the PIN code authentication provider.
 *
 * @template Claims - Type of claims collected during authentication (email, phone, etc.)
 */
export interface CodeProviderConfig<
	Claims extends Record<string, string> = Record<string, string>
> {
	/**
	 * The length of the generated PIN code.
	 * Common values are 4, 6, or 8 digits.
	 *
	 * @default 6
	 *
	 * @example
	 * ```ts
	 * {
	 *   length: 4 // 4-digit PIN for easier entry
	 * }
	 * ```
	 */
	readonly length?: number

	/**
	 * Request handler for rendering the authentication UI.
	 * Handles both the initial claim collection and PIN code entry screens.
	 *
	 * @param req - The HTTP request object
	 * @param state - Current authentication state (start or code verification)
	 * @param form - Form data from POST requests (if any)
	 * @param error - Authentication error to display (if any)
	 * @returns Promise resolving to the authentication page response
	 *
	 * @example
	 * ```ts
	 * request: async (req, state, form, error) => {
	 *   if (state.type === 'start') {
	 *     return new Response(renderClaimForm(form, error))
	 *   } else {
	 *     return new Response(renderCodeForm(state.claims.email, error))
	 *   }
	 * }
	 * ```
	 */
	request: (
		req: Request,
		state: CodeProviderState,
		form?: FormData,
		error?: CodeProviderError
	) => Promise<Response>

	/**
	 * Callback for sending PIN codes to users via their preferred method.
	 * Should handle delivery via email, SMS, or other communication channels.
	 *
	 * @param claims - User claims containing contact information
	 * @param code - The generated PIN code to send
	 * @returns Promise resolving to undefined on success, or error object on failure
	 *
	 * @example
	 * ```ts
	 * sendCode: async (claims, code) => {
	 *   try {
	 *     if (claims.email) {
	 *       await emailService.send({
	 *         to: claims.email,
	 *         subject: 'Your verification code',
	 *         text: `Your PIN code is: ${code}`
	 *       })
	 *     } else if (claims.phone) {
	 *       await smsService.send(claims.phone, `PIN: ${code}`)
	 *     } else {
	 *       return {
	 *         type: "invalid_claim",
	 *         key: "contact",
	 *         value: "No email or phone provided"
	 *       }
	 *     }
	 *   } catch (error) {
	 *     return {
	 *       type: "invalid_claim",
	 *       key: "delivery",
	 *       value: "Failed to send code"
	 *     }
	 *   }
	 * }
	 * ```
	 */
	sendCode: (claims: Claims, code: string) => Promise<CodeProviderError | undefined>
}

/**
 * Authentication flow states for the PIN code provider.
 * The provider transitions between these states during authentication.
 */
export type CodeProviderState =
	| {
			/** Initial state: user enters their claims (email, phone, etc.) */
			readonly type: "start"
	  }
	| {
			/** Code verification state: user enters the PIN code */
			readonly type: "code"
			/** Whether this is a code resend request */
			readonly resend?: boolean
			/** The generated PIN code for verification */
			readonly code: string
			/** User claims collected during the start phase */
			readonly claims: Record<string, string>
	  }

/**
 * Possible errors during PIN code authentication.
 */
export type CodeProviderError =
	| {
			/** The entered PIN code is incorrect */
			readonly type: "invalid_code"
	  }
	| {
			/** A user claim is invalid or missing */
			readonly type: "invalid_claim"
			/** The claim field that failed validation */
			readonly key: string
			/** The invalid value or error description */
			readonly value: string
	  }

/**
 * User data returned by successful PIN code authentication.
 *
 * @template Claims - Type of claims collected during authentication
 */
export interface CodeUserData<Claims extends Record<string, string> = Record<string, string>> {
	/** The verified claims collected during authentication */
	readonly claims: Claims
}

/**
 * Creates a PIN code authentication provider.
 * Implements a flexible claim-based authentication flow with PIN verification.
 *
 * @template Claims - Type of claims to collect (email, phone, username, etc.)
 * @param config - PIN code provider configuration
 * @returns Provider instance implementing PIN code authentication
 *
 * @example
 * ```ts
 * // Email-based PIN authentication
 * const emailCodeProvider = CodeProvider<{ email: string }>({
 *   length: 6,
 *   request: async (req, state, form, error) => {
 *     if (state.type === 'start') {
 *       return new Response(renderEmailForm(form?.get('email'), error))
 *     } else {
 *       return new Response(renderPinForm(state.claims.email, error, state.resend))
 *     }
 *   },
 *   sendCode: async (claims, code) => {
 *     if (!claims.email || !isValidEmail(claims.email)) {
 *       return {
 *         type: "invalid_claim",
 *         key: "email",
 *         value: "Invalid email address"
 *       }
 *     }
 *
 *     await emailService.send(claims.email, `Your verification code: ${code}`)
 *   }
 * })
 *
 * // Multi-channel PIN authentication (email or phone)
 * const flexibleCodeProvider = CodeProvider<{ email?: string; phone?: string }>({
 *   length: 4,
 *   request: async (req, state, form, error) => {
 *     if (state.type === 'start') {
 *       return new Response(renderContactForm(form, error))
 *     } else {
 *       const contact = state.claims.email || state.claims.phone
 *       return new Response(renderPinForm(contact, error))
 *     }
 *   },
 *   sendCode: async (claims, code) => {
 *     if (claims.email) {
 *       await emailService.send(claims.email, `PIN: ${code}`)
 *     } else if (claims.phone) {
 *       await smsService.send(claims.phone, `PIN: ${code}`)
 *     } else {
 *       return {
 *         type: "invalid_claim",
 *         key: "contact",
 *         value: "Provide either email or phone number"
 *       }
 *     }
 *   }
 * })
 *
 * // Usage in issuer
 * export default issuer({
 *   providers: {
 *     email: emailCodeProvider,
 *     flexible: flexibleCodeProvider
 *   },
 *   success: async (ctx, value) => {
 *     if (value.provider === "code") {
 *       const email = value.claims.email
 *       const phone = value.claims.phone
 *
 *       // Look up or create user based on verified claims
 *       const userId = await findOrCreateUser({ email, phone })
 *
 *       return ctx.subject("user", { userId, email, phone })
 *     }
 *   }
 * })
 * ```
 */
export const CodeProvider = <Claims extends Record<string, string> = Record<string, string>>(
	config: CodeProviderConfig<Claims>
): Provider<CodeUserData<Claims>> => {
	const codeLength = config.length || 6

	/**
	 * Generates a cryptographically secure PIN code.
	 */
	const generateCode = (): string => {
		return generateUnbiasedDigits(codeLength)
	}

	return {
		type: "code",

		init(routes, ctx) {
			/**
			 * Transitions between authentication states and renders the appropriate UI.
			 */
			const transition = async (
				c: Context,
				nextState: CodeProviderState,
				formData?: FormData,
				error?: CodeProviderError
			): Promise<Response> => {
				await ctx.set<CodeProviderState>(c, "provider", 60 * 60 * 24, nextState)
				const response = await config.request(c.req.raw, nextState, formData, error)
				return ctx.forward(c, response)
			}

			/**
			 * GET /authorize - Display initial claim collection form
			 */
			routes.get("/authorize", async (c) => {
				return transition(c, { type: "start" })
			})

			/**
			 * POST /authorize - Handle form submissions and state transitions
			 */
			routes.post("/authorize", async (c) => {
				const formData = await c.req.formData()
				const currentState = await ctx.get<CodeProviderState>(c, "provider")
				const action = formData.get("action")?.toString()

				// Handle claim submission and code generation
				if (action === "request" || action === "resend") {
					const code = generateCode()
					const formEntries = Object.fromEntries(formData)
					const { action: _, ...claims } = formEntries as Claims & { action?: string }

					// Send PIN code and handle any errors
					const sendError = await config.sendCode(claims as Claims, code)
					if (sendError) {
						return transition(c, { type: "start" }, formData, sendError)
					}

					return transition(
						c,
						{
							type: "code",
							resend: action === "resend",
							claims: claims as Record<string, string>,
							code
						},
						formData
					)
				}

				// Handle PIN code verification
				if (action === "verify" && currentState?.type === "code") {
					const enteredCode = formData.get("code")?.toString()

					if (
						!currentState.code ||
						!enteredCode ||
						!timingSafeCompare(currentState.code, enteredCode)
					) {
						return transition(
							c,
							{
								...currentState,
								resend: false
							},
							formData,
							{ type: "invalid_code" }
						)
					}

					// PIN verification successful - complete authentication
					await ctx.unset(c, "provider")
					const successResponse = await ctx.success(c, {
						claims: currentState.claims as Claims
					})
					return ctx.forward(c, successResponse)
				}

				// Default: return to start state
				return transition(c, { type: "start" }, formData)
			})
		}
	}
}

/**
 * Type helper for CodeProvider configuration options.
 * @internal
 */
export type CodeProviderOptions = Parameters<typeof CodeProvider>[0]
