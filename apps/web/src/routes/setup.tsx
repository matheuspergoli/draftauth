import { env } from "@/environment/env"
import { api } from "@/libs/api"
import { auth } from "@/libs/auth"
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle
} from "@/shared/components/card"
import { useAppForm } from "@/shared/components/form"
import { Input } from "@/shared/components/input"
import { Label } from "@/shared/components/label"
import { createFileRoute, redirect } from "@tanstack/react-router"
import { z } from "zod"

export const Route = createFileRoute("/setup")({
	component: RouteComponent,
	beforeLoad: async () => {
		const response = await api.setup.status.$get()
		const data = await response.json()

		if (data.setupComplete) throw redirect({ to: "/dashboard" })
	}
})

const SetupSchema = z.object({
	redirectURI: z.string().url("URI precisa ser um endereço válido"),
	appName: z
		.string()
		.min(3, "Nome da aplicação deve ter no mínimo 3 caracteres")
		.max(50, "Nome da aplicação deve ter no máximo 50 caracteres")
})

type SetupData = z.infer<typeof SetupSchema>

function RouteComponent() {
	const search = Route.useSearch()

	const form = useAppForm({
		defaultValues: {
			appName: "",
			redirectURI: ""
		} as SetupData,
		validators: {
			onSubmit: SetupSchema
		},
		onSubmit: async ({ value }) => {
			await api.setup.initialize.$post({
				json: {
					state: search.state,
					appName: value.appName,
					redirectURI: value.redirectURI
				}
			})

			await auth.login()
		}
	})

	return (
		<main className="h-dvh w-screen flex flex-col items-center justify-center">
			<Card className="max-w-xl w-full">
				<CardHeader>
					<CardTitle>Crie a primeira aplicação</CardTitle>
					<CardDescription>
						Esse é o setup inicial para começar a usar o Draft Auth
					</CardDescription>
				</CardHeader>
				<CardContent>
					<form
						className="space-y-3"
						onSubmit={(e) => {
							e.preventDefault()
							e.stopPropagation()
							form.handleSubmit()
						}}
					>
						<fieldset className="space-y-1">
							<Label>ID da Aplicação Principal será fixo</Label>
							<Input defaultValue={env.VITE_APPLICATION_ID} disabled />
						</fieldset>

						<form.AppField name="appName">
							{(field) => (
								<field.Fieldset>
									<field.LabelField>Nome da Aplicação</field.LabelField>
									<field.TextField placeholder="Ex:. E-Commerce App" />
									<field.ErrorMessages />
								</field.Fieldset>
							)}
						</form.AppField>

						<form.AppField name="redirectURI">
							{(field) => (
								<field.Fieldset>
									<field.LabelField>URI de Redirecionamento</field.LabelField>
									<field.TextField placeholder="Ex:. https://" />
									<field.ErrorMessages />
								</field.Fieldset>
							)}
						</form.AppField>

						<form.AppForm>
							<form.SubscribeButton>Criar</form.SubscribeButton>
						</form.AppForm>
					</form>
				</CardContent>
			</Card>
		</main>
	)
}
