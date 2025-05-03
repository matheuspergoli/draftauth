import { type BaseColor, baseColors } from "@/libs/colors"
import React from "react"

type ColorMode = "dark" | "light" | "system"
type ThemeName = BaseColor["name"] | "default"

interface ThemeProviderProps {
	children: React.ReactNode
	defaultColorMode?: ColorMode
	defaultTheme?: ThemeName
	colorModeStorageKey?: string
	themeStorageKey?: string
}

interface ThemeContextValue {
	colorMode: ColorMode
	setColorMode: (mode: ColorMode) => void
	theme: ThemeName
	setTheme: (theme: ThemeName) => void
}

const DEFAULT_COLOR_MODE = "system"
const DEFAULT_THEME = "default"

const ThemeContext = React.createContext<ThemeContextValue | undefined>(undefined)

const isValidTheme = (theme: string): theme is ThemeName => {
	return baseColors.some((color) => color.name === theme)
}

const isValidColorMode = (mode: string): mode is ColorMode => {
	return ["dark", "light", "system"].includes(mode)
}

export const ThemeProvider = ({
	children,
	defaultColorMode = DEFAULT_COLOR_MODE,
	defaultTheme = DEFAULT_THEME,
	colorModeStorageKey = "app-color-mode",
	themeStorageKey = "app-theme"
}: ThemeProviderProps) => {
	const [colorMode, setColorModeState] = React.useState<ColorMode>(() => {
		const storedColorMode = localStorage.getItem(colorModeStorageKey)
		if (storedColorMode && isValidColorMode(storedColorMode)) {
			return storedColorMode
		}
		return isValidColorMode(defaultColorMode) ? defaultColorMode : DEFAULT_COLOR_MODE
	})

	const [theme, setThemeState] = React.useState<ThemeName>(() => {
		const storedTheme = localStorage.getItem(themeStorageKey)
		if (storedTheme && isValidTheme(storedTheme)) {
			return storedTheme
		}
		return isValidTheme(defaultTheme) ? defaultTheme : DEFAULT_THEME
	})

	const setColorMode = React.useCallback(
		(mode: ColorMode) => {
			localStorage.setItem(colorModeStorageKey, mode)
			setColorModeState(mode)
		},
		[colorModeStorageKey]
	)

	const setTheme = React.useCallback(
		(newTheme: ThemeName) => {
			localStorage.setItem(themeStorageKey, newTheme)
			setThemeState(newTheme)
		},
		[themeStorageKey]
	)

	React.useEffect(() => {
		const root = window.document.documentElement
		root.classList.remove("light", "dark")

		if (colorMode === "system") {
			const systemColorMode = window.matchMedia("(prefers-color-scheme: dark)").matches
				? "dark"
				: "light"
			root.classList.add(systemColorMode)
		} else {
			root.classList.add(colorMode)
		}
	}, [colorMode])

	React.useEffect(() => {
		const body = window.document.body

		for (const className of Array.from(body.classList)) {
			if (className.startsWith("theme-")) {
				body.classList.remove(className)
			}
		}

		body.classList.add(`theme-${theme}`)

		if (theme.endsWith("-scaled")) {
			body.classList.add("theme-scaled")
		}
	}, [theme])

	const value = React.useMemo(
		() => ({
			colorMode,
			setColorMode,
			theme,
			setTheme
		}),
		[colorMode, setColorMode, theme, setTheme]
	)

	return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}

export const useTheme = () => {
	const context = React.useContext(ThemeContext)

	if (context === undefined) {
		throw new Error("useTheme must be used within a ThemeProvider")
	}

	return context
}
