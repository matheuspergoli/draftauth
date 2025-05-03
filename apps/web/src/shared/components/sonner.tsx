import { Toaster as Sonner, type ToasterProps } from "sonner"
import { useTheme } from "./theming"

const Toaster = ({ ...props }: ToasterProps) => {
	const { colorMode } = useTheme()

	return (
		<Sonner
			theme={colorMode as ToasterProps["theme"]}
			className="toaster group"
			style={
				{
					"--normal-bg": "var(--popover)",
					"--normal-text": "var(--popover-foreground)",
					"--normal-border": "var(--border)"
				} as React.CSSProperties
			}
			{...props}
		/>
	)
}

export { Toaster }
