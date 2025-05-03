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
					label: "Comece Aqui",
					items: [
						{ label: "Introdução", slug: "guides/intro" },
						{ label: "Guia Rápido", slug: "guides/quickstart" },
						{ label: "Variáveis de Ambiente", slug: "guides/environment-variables" }
					]
				},
				{
					label: "Conceitos Fundamentais",
					items: [
						{ label: "Autenticação", slug: "concepts/authentication" },
						{ label: "Autorização (RBAC)", slug: "concepts/authorization" },
						{ label: "Aplicações", slug: "concepts/applications" },
						{ label: "Usuários", slug: "concepts/users" },
						{ label: "API Keys", slug: "concepts/api-keys" },
						{ label: "Autenticação HMAC", slug: "concepts/hmac" }
					]
				},
				{
					label: "API Reference",
					items: [
						{ label: "Management API", slug: "api/management" },
						{ label: "Service API", slug: "api/service" },
						{ label: "Setup API", slug: "api/setup" }
					]
				},
				{
					label: "Guias",
					items: [
						{ label: "Configurando Provedores OAuth", slug: "guides/oauth-providers" },
						{ label: "Protegendo API com HMAC", slug: "guides/protecting-api-hmac" },
						{ label: "Gerenciando Acesso por Aplicação", slug: "guides/app-access-management" }
					]
				}
			]
		})
	]
})
