/**
 * Pre-built UI component for OAuth provider selection.
 * Displays a clean selection interface where users can choose their preferred authentication method.
 *
 * ## Features
 *
 * - **Multiple providers**: Support for popular OAuth providers with built-in icons
 * - **Customizable displays**: Override provider names and copy text
 * - **Conditional visibility**: Hide specific providers using configuration
 * - **Type safety**: Full TypeScript support with autocomplete for known providers
 * - **Accessibility**: Proper ARIA labels and semantic markup
 *
 * ## Usage
 *
 * ```ts
 * import { Select } from "@draftauth/core/ui/select"
 *
 * export default issuer({
 *   select: Select({
 *     copy: {
 *       button_provider: "Continuar com"
 *     },
 *     displays: {
 *       code: "Código PIN",
 *       github: "Conta GitHub"
 *     },
 *     providers: {
 *       github: {
 *         hide: true
 *       },
 *       google: {
 *         display: "Google"
 *       }
 *     }
 *   })
 *   // ...
 * })
 * ```
 *
 * ## Provider Configuration
 *
 * Each provider can be individually configured:
 *
 * - **hide**: Boolean to control visibility
 * - **display**: Custom display name override
 *
 * Global display overrides are applied through the `displays` property, which affects
 * all providers of that type unless specifically overridden at the provider level.
 *
 * @packageDocumentation
 */
/** @jsxImportSource hono/jsx */

import type { JSX } from "hono/jsx/jsx-runtime"
import { Layout } from "./base"
import { ICON_GITHUB, ICON_GOOGLE } from "./icon"

/**
 * Default copy text used throughout the select UI.
 * These values are used when no custom copy is provided.
 */
const DEFAULT_COPY = {
	/**
	 * Copy for the provider button prefix text.
	 * @example "Continue with GitHub" where "Continue with" is this value
	 */
	button_provider: "Continue with"
}

/**
 * Default display names for all known provider types.
 * These provide consistent naming across the application and serve as fallbacks
 * when no custom display name is configured.
 */
const DEFAULT_DISPLAY = {
	steam: "Steam",
	twitch: "Twitch",
	google: "Google",
	github: "GitHub",
	apple: "Apple",
	code: "Code",
	x: "X",
	facebook: "Facebook",
	microsoft: "Microsoft",
	slack: "Slack",
	password: "Password"
}

/**
 * Customizable copy text for the Select UI component.
 * Allows overriding default text to support internationalization or custom branding.
 */
export type SelectCopy = typeof DEFAULT_COPY

/**
 * Union type of all known provider types that have default display names and icons.
 * These types get autocompletion support in the displays configuration.
 */
export type KnownProviderType = keyof typeof DEFAULT_DISPLAY

/**
 * Configuration options for individual providers in the select UI.
 * Each provider can be individually controlled and customized.
 */
export interface ProviderConfig {
	/**
	 * Whether to hide the provider from the select UI.
	 * When true, the provider will not appear in the selection interface.
	 *
	 * @default false
	 */
	hide?: boolean

	/**
	 * Custom display name for this specific provider instance.
	 * Overrides both the default display name and any global display override.
	 *
	 * @example "My Custom Google Login"
	 */
	display?: string
}

/**
 * Configuration properties for the Select UI component.
 * Provides comprehensive customization of appearance and behavior.
 */
export interface SelectProps {
	/**
	 * Provider-specific configurations mapped by provider key.
	 * Each key corresponds to a provider instance, allowing individual customization.
	 *
	 * @example
	 * ```ts
	 * {
	 *   github: {
	 *     hide: true
	 *   },
	 *   google: {
	 *     display: "Google Account"
	 *   },
	 *   "custom-provider": {
	 *     display: "Custom OAuth"
	 *   }
	 * }
	 * ```
	 */
	providers?: Record<string, ProviderConfig>

	/**
	 * Custom copy text overrides for UI elements.
	 * Useful for internationalization and custom branding.
	 *
	 * @example
	 * ```ts
	 * {
	 *   button_provider: "Sign in with"
	 * }
	 * ```
	 */
	copy?: Partial<SelectCopy>

	/**
	 * Global display name overrides for provider types.
	 *
	 * This allows you to override the default display names globally for all providers
	 * of a specific type. For known provider types, you get full autocompletion support.
	 * Custom provider types are also supported.
	 *
	 * The priority order for display names is:
	 * 1. Provider-specific `display` in `providers` config
	 * 2. Type-specific `displays` override (this property)
	 * 3. Default display name from `DEFAULT_DISPLAY`
	 * 4. Provider type string as fallback
	 *
	 * @example
	 * ```ts
	 * {
	 *   displays: {
	 *     code: "PIN Code",        // ✅ Autocomplete available
	 *     github: "GitHub Account", // ✅ Autocomplete available
	 *     customType: "Custom"     // ✅ Also works for unknown types
	 *   }
	 * }
	 * ```
	 */
	displays?: Partial<Record<KnownProviderType, string>> & Record<string, string>
}

/**
 * Type definition for JSX elements used as provider icons.
 * Ensures type safety when working with icon elements.
 */
type IconElement = JSX.Element

/**
 * Comprehensive icon mapping for all supported authentication providers.
 * Each icon is an optimized SVG component with proper accessibility attributes.
 *
 * Icons are designed to:
 * - Scale properly at different sizes
 * - Inherit text color for theming
 * - Include proper ARIA attributes
 * - Work with screen readers
 */
const ICON: Record<string, IconElement> = {
	steam: (
		<svg
			aria-hidden="true"
			class="bi bi-steam"
			fill="currentColor"
			height="16"
			viewBox="0 0 16 16"
			width="16"
			xmlns="http://www.w3.org/2000/svg"
		>
			<path d="M.329 10.333A8.01 8.01 0 0 0 7.99 16C12.414 16 16 12.418 16 8s-3.586-8-8.009-8A8.006 8.006 0 0 0 0 7.468l.003.006 4.304 1.769A2.2 2.2 0 0 1 5.62 8.88l1.96-2.844-.001-.04a3.046 3.046 0 0 1 3.042-3.043 3.046 3.046 0 0 1 3.042 3.043 3.047 3.047 0 0 1-3.111 3.044l-2.804 2a2.223 2.223 0 0 1-3.075 2.11 2.22 2.22 0 0 1-1.312-1.568L.33 10.333Z" />
			<path d="M4.868 12.683a1.715 1.715 0 0 0 1.318-3.165 1.7 1.7 0 0 0-1.263-.02l1.023.424a1.261 1.261 0 1 1-.97 2.33l-.99-.41a1.7 1.7 0 0 0 .882.84Zm3.726-6.687a2.03 2.03 0 0 0 2.027 2.029 2.03 2.03 0 0 0 2.027-2.029 2.03 2.03 0 0 0-2.027-2.027 2.03 2.03 0 0 0-2.027 2.027m2.03-1.527a1.524 1.524 0 1 1-.002 3.048 1.524 1.524 0 0 1 .002-3.048" />
		</svg>
	),
	code: (
		<svg
			aria-hidden="true"
			data-name="Layer 1"
			fill="currentColor"
			viewBox="0 0 52 52"
			xmlns="http://www.w3.org/2000/svg"
		>
			<path
				d="M8.55,36.91A6.55,6.55,0,1,1,2,43.45,6.54,6.54,0,0,1,8.55,36.91Zm17.45,0a6.55,6.55,0,1,1-6.55,6.54A6.55,6.55,0,0,1,26,36.91Zm17.45,0a6.55,6.55,0,1,1-6.54,6.54A6.54,6.54,0,0,1,43.45,36.91ZM8.55,19.45A6.55,6.55,0,1,1,2,26,6.55,6.55,0,0,1,8.55,19.45Zm17.45,0A6.55,6.55,0,1,1,19.45,26,6.56,6.56,0,0,1,26,19.45Zm17.45,0A6.55,6.55,0,1,1,36.91,26,6.55,6.55,0,0,1,43.45,19.45ZM8.55,2A6.55,6.55,0,1,1,2,8.55,6.54,6.54,0,0,1,8.55,2ZM26,2a6.55,6.55,0,1,1-6.55,6.55A6.55,6.55,0,0,1,26,2ZM43.45,2a6.55,6.55,0,1,1-6.54,6.55A6.55,6.55,0,0,1,43.45,2Z"
				fill-rule="evenodd"
			/>
		</svg>
	),
	password: (
		<svg
			aria-hidden="true"
			fill="currentColor"
			viewBox="0 0 24 24"
			xmlns="http://www.w3.org/2000/svg"
		>
			<path
				clip-rule="evenodd"
				d="M12 1.5a5.25 5.25 0 0 0-5.25 5.25v3a3 3 0 0 0-3 3v6.75a3 3 0 0 0 3 3h10.5a3 3 0 0 0 3-3v-6.75a3 3 0 0 0-3-3v-3c0-2.9-2.35-5.25-5.25-5.25Zm3.75 8.25v-3a3.75 3.75 0 1 0-7.5 0v3h7.5Z"
				fill-rule="evenodd"
			/>
		</svg>
	),
	twitch: (
		<svg
			aria-hidden="true"
			role="img"
			viewBox="0 0 448 512"
			xmlns="http://www.w3.org/2000/svg"
		>
			<path
				d="M40.1 32L10 108.9v314.3h107V480h60.2l56.8-56.8h87l117-117V32H40.1zm357.8 254.1L331 353H224l-56.8 56.8V353H76.9V72.1h321v214zM331 149v116.9h-40.1V149H331zm-107 0v116.9h-40.1V149H224z"
				fill="currentColor"
			/>
		</svg>
	),
	google: ICON_GOOGLE,
	github: ICON_GITHUB,
	apple: (
		<svg
			aria-hidden="true"
			role="img"
			viewBox="0 0 814 1000"
			xmlns="http://www.w3.org/2000/svg"
		>
			<path
				d="M788.1 340.9c-5.8 4.5-108.2 62.2-108.2 190.5 0 148.4 130.3 200.9 134.2 202.2-.6 3.2-20.7 71.9-68.7 141.9-42.8 61.6-87.5 123.1-155.5 123.1s-85.5-39.5-164-39.5c-76.5 0-103.7 40.8-165.9 40.8s-105.6-57-155.5-127C46.7 790.7 0 663 0 541.8c0-194.4 126.4-297.5 250.8-297.5 66.1 0 121.2 43.4 162.7 43.4 39.5 0 101.1-46 176.3-46 28.5 0 130.9 2.6 198.3 99.2zm-234-181.5c31.1-36.9 53.1-88.1 53.1-139.3 0-7.1-.6-14.3-1.9-20.1-50.6 1.9-110.8 33.7-147.1 75.8-28.5 32.4-55.1 83.6-55.1 135.5 0 7.8 1.3 15.6 1.9 18.1 3.2.6 8.4 1.3 13.6 1.3 45.4 0 102.5-30.4 135.5-71.3z "
				fill="currentColor"
			/>
		</svg>
	),
	x: (
		<svg
			aria-hidden="true"
			role="img"
			viewBox="0 0 1200 1227"
			xmlns="http://www.w3.org/2000/svg"
		>
			<path
				d="M714.163 519.284 1160.89 0h-105.86L667.137 450.887 357.328 0H0l468.492 681.821L0 1226.37h105.866l409.625-476.152 327.181 476.152H1200L714.137 519.284h.026ZM569.165 687.828l-47.468-67.894-377.686-540.24h162.604l304.797 435.991 47.468 67.894 396.2 566.721H892.476L569.165 687.854v-.026Z"
				fill="currentColor"
			/>
		</svg>
	),
	microsoft: (
		<svg
			aria-hidden="true"
			preserveAspectRatio="xMidYMid"
			role="img"
			viewBox="0 0 256 256"
			xmlns="http://www.w3.org/2000/svg"
		>
			<path d="M121.666 121.666H0V0h121.666z" fill="#F1511B" />
			<path d="M256 121.666H134.335V0H256z" fill="#80CC28" />
			<path d="M121.663 256.002H0V134.336h121.663z" fill="#00ADEF" />
			<path d="M256 256.002H134.335V134.336H256z" fill="#FBBC09" />
		</svg>
	),
	facebook: (
		<svg
			aria-hidden="true"
			fill="url(#a)"
			role="img"
			viewBox="0 0 36 36"
			xmlns="http://www.w3.org/2000/svg"
		>
			<defs>
				<linearGradient id="a" x1="50%" x2="50%" y1="97.078%" y2="0%">
					<stop offset="0%" stop-color="#0062E0" />
					<stop offset="100%" stop-color="#19AFFF" />
				</linearGradient>
			</defs>
			<path d="M15 35.8C6.5 34.3 0 26.9 0 18 0 8.1 8.1 0 18 0s18 8.1 18 18c0 8.9-6.5 16.3-15 17.8l-1-.8h-4l-1 .8z" />
			<path
				d="m25 23 .8-5H21v-3.5c0-1.4.5-2.5 2.7-2.5H26V7.4c-1.3-.2-2.7-.4-4-.4-4.1 0-7 2.5-7 7v4h-4.5v5H15v12.7c1 .2 2 .3 3 .3s2-.1 3-.3V23h4z"
				fill="#FFF"
			/>
		</svg>
	),
	slack: (
		<svg
			aria-hidden="true"
			enable-background="new 0 0 2447.6 2452.5"
			role="img"
			viewBox="0 0 2447.6 2452.5"
			xmlns="http://www.w3.org/2000/svg"
		>
			<g clip-rule="evenodd" fill-rule="evenodd">
				<path
					d="m897.4 0c-135.3.1-244.8 109.9-244.7 245.2-.1 135.3 109.5 245.1 244.8 245.2h244.8v-245.1c.1-135.3-109.5-245.1-244.9-245.3.1 0 .1 0 0 0m0 654h-652.6c-135.3.1-244.9 109.9-244.8 245.2-.2 135.3 109.4 245.1 244.7 245.3h652.7c135.3-.1 244.9-109.9 244.8-245.2.1-135.4-109.5-245.2-244.8-245.3z"
					fill="#36c5f0"
				/>
				<path
					d="m2447.6 899.2c.1-135.3-109.5-245.1-244.8-245.2-135.3.1-244.9 109.9-244.8 245.2v245.3h244.8c135.3-.1 244.9-109.9 244.8-245.3zm-652.7 0v-654c.1-135.2-109.4-245-244.7-245.2-135.3.1-244.9 109.9-244.8 245.2v654c-.2 135.3 109.4 245.1 244.7 245.3 135.3-.1 244.9-109.9 244.8-245.3z"
					fill="#2eb67d"
				/>
				<path
					d="m1550.1 2452.5c135.3-.1 244.9-109.9 244.8-245.2.1-135.3-109.5-245.1-244.8-245.2h-244.8v245.2c-.1 135.2 109.5 245 244.8 245.2zm0-654.1h652.7c135.3-.1 244.9-109.9 244.8-245.2.2-135.3-109.4-245.1-244.7-245.3h-652.7c-135.3.1-244.9 109.9-244.8 245.2-.1 135.4 109.4 245.2 244.7 245.3z"
					fill="#ecb22e"
				/>
				<path
					d="m0 1553.2c-.1 135.3 109.5 245.1 244.8 245.2 135.3-.1 244.9-109.9 244.8-245.2v-245.2h-244.8c-135.3.1-244.9 109.9-244.8 245.2zm652.7 0v654c-.2 135.3 109.4 245.1 244.7 245.3 135.3-.1 244.9-109.9 244.8-245.2v-653.9c.2-135.3-109.4-245.1-244.7-245.3-135.4 0-244.9 109.8-244.8 245.1 0 0 0 .1 0 0"
					fill="#e01e5a"
				/>
			</g>
		</svg>
	)
} as const

/**
 * Creates a provider selection UI component for OAuth authentication.
 *
 * This component generates a complete authentication provider selection interface that:
 * - Displays available OAuth providers as clickable buttons
 * - Includes appropriate icons for recognized providers
 * - Supports custom theming and internationalization
 * - Provides accessible markup with proper ARIA attributes
 * - Handles provider visibility and custom display names
 *
 * @param props - Configuration options for customizing the select UI
 * @returns An async function that generates the HTML response for the selection interface
 *
 * @example
 * ```ts
 * // Basic usage with defaults
 * const selectUI = Select()
 *
 * // Customized with provider configuration
 * const selectUI = Select({
 *   copy: {
 *     button_provider: "Sign in with"
 *   },
 *   displays: {
 *     github: "GitHub Account",
 *     code: "Email Code"
 *   },
 *   providers: {
 *     facebook: { hide: true },
 *     google: { display: "Google Workspace" }
 *   }
 * })
 *
 * // Use in issuer configuration
 * export default issuer({
 *   select: selectUI,
 *   // ... other configuration
 * })
 * ```
 *
 * ## Provider Resolution Logic
 *
 * Display names are resolved in the following priority order:
 * 1. Provider-specific `display` property
 * 2. Global `displays` type override
 * 3. Default display name from `DEFAULT_DISPLAY`
 * 4. Provider type string as final fallback
 *
 * ## Accessibility Features
 *
 * The generated UI includes:
 * - Semantic HTML structure
 * - Proper button roles and keyboard navigation
 * - Icon accessibility with `aria-hidden="true"`
 * - Screen reader friendly provider names
 */
export const Select = (props?: SelectProps) => {
	return async (providers: Record<string, string>, _req: Request): Promise<Response> => {
		// Merge user copy with defaults, ensuring type safety
		const copy: SelectCopy = {
			...DEFAULT_COPY,
			...props?.copy
		}

		// Create complete displays mapping with user overrides
		const displays: Record<string, string> = {
			...DEFAULT_DISPLAY,
			...props?.displays
		}

		// Generate the selection interface JSX
		const jsx = (
			<Layout>
				<div data-component="form">
					{Object.entries(providers)
						.map(([providerKey, providerType]) => {
							// Get provider-specific configuration
							const providerConfig = props?.providers?.[providerKey]

							// Skip hidden providers
							if (providerConfig?.hide) return null

							// Resolve display name with priority order
							const displayName =
								providerConfig?.display || // 1. Provider-specific override
								displays[providerType] || // 2. Global type override
								providerType // 3. Fallback to type string

							// Get icon for the provider (if available)
							const icon = ICON[providerKey]

							return (
								<a
									aria-label={`${copy.button_provider} ${displayName}`}
									data-color="ghost"
									data-component="button"
									href={`/${providerKey}/authorize`}
									key={`${providerKey}-${providerType}`}
								>
									{icon && <i data-slot="icon">{icon}</i>}
									{copy.button_provider} {displayName}
								</a>
							)
						})
						.filter((element): element is JSX.Element => element !== null)}
				</div>
			</Layout>
		)

		return new Response(jsx.toString(), {
			headers: {
				"Content-Type": "text/html"
			}
		})
	}
}
