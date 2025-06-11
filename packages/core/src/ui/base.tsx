import type { PropsWithChildren } from "hono/jsx"
import { getTheme } from "../themes/theme"
import css from "./ui.css" assert { type: "text" }

/**
 * Base layout component for Draft Auth UI.
 * Provides theming, responsive design, and consistent styling across all auth screens.
 *
 * ## Features
 *
 * - **Theme Support**: Light/dark mode with custom colors and fonts
 * - **Responsive Design**: Adapts to different screen sizes
 * - **Custom Branding**: Support for custom logos and styling
 * - **CSS Variables**: Uses CSS custom properties for theming
 *
 * @example
 * ```tsx
 * <Layout size="small">
 *   <div>Your auth form content</div>
 * </Layout>
 * ```
 */

/**
 * Props for the Layout component.
 */
export interface LayoutProps {
	/**
	 * Optional size variant for the layout container.
	 *
	 * @default undefined (normal size)
	 */
	readonly size?: "small"
}

/**
 * Main layout component that wraps all authentication UI screens.
 * Handles theming, logo display, and provides consistent styling.
 *
 * @param props - Layout props including children and optional size
 * @returns Complete HTML document with theming and branding applied
 */
export const Layout = (props: PropsWithChildren<LayoutProps>) => {
	const theme = getTheme()

	/**
	 * Gets a theme value for a specific key and color mode.
	 * Handles both string values and light/dark object configurations.
	 */
	const getThemeValue = (
		key: "primary" | "background" | "logo",
		mode: "light" | "dark"
	): string | undefined => {
		if (!theme || !theme[key]) return undefined

		if (typeof theme[key] === "string") {
			return theme[key] as string
		}

		return (theme[key] as Record<string, string>)[mode]
	}

	/**
	 * Calculates border radius value based on theme configuration.
	 */
	const getBorderRadius = (): string => {
		switch (theme?.radius) {
			case "none":
				return "0"
			case "sm":
				return "1"
			case "md":
				return "1.25"
			case "lg":
				return "1.5"
			case "full":
				return "1000000000001"
			default:
				return "1"
		}
	}

	/**
	 * Checks if both light and dark logo variants are available.
	 */
	const hasCustomLogo = Boolean(
		getThemeValue("logo", "light") && getThemeValue("logo", "dark")
	)

	/**
	 * CSS custom properties for theming.
	 */
	const themeStyles = {
		"--color-background-light": getThemeValue("background", "light"),
		"--color-background-dark": getThemeValue("background", "dark"),
		"--color-primary-light": getThemeValue("primary", "light"),
		"--color-primary-dark": getThemeValue("primary", "dark"),
		"--font-family": theme?.font?.family,
		"--font-scale": theme?.font?.scale,
		"--border-radius": getBorderRadius()
	}

	return (
		<html lang="en" style={themeStyles}>
			<head>
				<title>{theme?.title || "Draft Auth"}</title>
				<meta charset="utf-8" />
				<meta name="viewport" content="width=device-width, initial-scale=1" />

				{/* Favicon handling */}
				{theme?.favicon ? (
					<link rel="icon" href={theme.favicon} />
				) : (
					<>
						<link rel="icon" href="https://openauth.js.org/favicon.ico" sizes="48x48" />
						<link
							rel="icon"
							href="https://openauth.js.org/favicon.svg"
							media="(prefers-color-scheme: light)"
						/>
						<link
							rel="icon"
							href="https://openauth.js.org/favicon-dark.svg"
							media="(prefers-color-scheme: dark)"
						/>
						<link
							rel="shortcut icon"
							href="https://openauth.js.org/favicon.svg"
							type="image/svg+xml"
						/>
					</>
				)}

				{/* Base CSS styles */}
				<style dangerouslySetInnerHTML={{ __html: css }} />

				{/* Custom theme CSS if provided */}
				{theme?.css && <style dangerouslySetInnerHTML={{ __html: theme.css }} />}
			</head>
			<body>
				<div data-component="root">
					<div data-component="center" data-size={props.size}>
						{/* Logo section */}
						{hasCustomLogo ? (
							<>
								<img
									alt="Logo Light"
									data-component="logo"
									src={getThemeValue("logo", "light")}
									data-mode="light"
								/>
								<img
									alt="Logo Dark"
									data-component="logo"
									src={getThemeValue("logo", "dark")}
									data-mode="dark"
								/>
							</>
						) : (
							<DefaultDraftAuthLogo />
						)}

						{/* Main content */}
						{props.children}
					</div>
				</div>
			</body>
		</html>
	)
}

/**
 * Default Draft Auth logo component.
 * Used when no custom logo is provided in the theme configuration.
 */
const DefaultDraftAuthLogo = () => (
	<svg
		data-component="logo-default"
		width="51"
		height="51"
		viewBox="0 0 51 51"
		fill="none"
		xmlns="http://www.w3.org/2000/svg"
		aria-label="Draft Auth Logo"
	>
		<path
			d="M0 50.2303V0.12854H50.1017V50.2303H0ZM3.08002 11.8326H11.7041V3.20856H3.08002V11.8326ZM14.8526 11.8326H23.4766V3.20856H14.8526V11.8326ZM26.5566 11.8326H35.1807V3.20856H26.5566V11.8326ZM38.3292 11.8326H47.0217V3.20856H38.3292V11.8326ZM3.08002 23.6052H11.7041V14.9811H3.08002V23.6052ZM14.8526 23.6052H23.4766V14.9811H14.8526V23.6052ZM26.5566 23.6052H35.1807V14.9811H26.5566V23.6052ZM38.3292 23.6052H47.0217V14.9811H38.3292V23.6052ZM3.08002 35.3092H11.7041V26.6852H3.08002V35.3092ZM14.8526 35.3092H23.4766V26.6852H14.8526V35.3092ZM26.5566 35.3092H35.1807V26.6852H26.5566V35.3092ZM38.3292 35.3092H47.0217V26.6852H38.3292V35.3092ZM3.08002 47.1502H11.7041V38.3893H3.08002V47.1502ZM14.8526 47.1502H23.4766V38.3893H14.8526V47.1502ZM26.5566 47.1502H35.1807V38.3893H26.5566V47.1502ZM38.3292 47.1502H47.0217V38.3893H38.3292V47.1502Z"
			fill="currentColor"
		/>
	</svg>
)
