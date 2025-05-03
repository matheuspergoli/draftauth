import type { Theme } from "@openauthjs/openauth/ui/theme"

export const CUSTOM_THEME: Theme = {
	title: "Draft Auth",
	background: {
		dark: "black",
		light: "white"
	},
	primary: {
		dark: "white",
		light: "black"
	},
	font: {
		family: "Geist, sans-serif"
	},
	css: `
    @import url("https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&family=Geist:wght@100..900&display=swap");
  `
}
