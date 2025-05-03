import { defineConfig } from "astro/config"
import starlight from "@astrojs/starlight"

export default defineConfig({
	integrations: [
		starlight({
			title: "Draft Auth",
			social: [
				{
					icon: "github",
					label: "GitHub",
					href: "https://github.com/matheuspergoli/draftauth"
				},
				{
					icon: "linkedin",
					label: "LinkedIn",
					href: "https://www.linkedin.com/in/matheuspergoli"
				}
			],
			sidebar: [
				{
					label: "Comece aqui",
					items: [{ label: "Introdução", slug: "guides/intro" }]
				}
			]
		})
	]
})
