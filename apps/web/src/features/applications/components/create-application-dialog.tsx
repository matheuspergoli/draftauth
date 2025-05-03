import { Button } from "@/shared/components/button"
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogHeader,
	DialogTitle,
	DialogTrigger
} from "@/shared/components/dialog"
import { useAppForm } from "@/shared/components/form"
import { Plus } from "lucide-react"
import { useCreateApplication } from "../hooks/use-create-application"
import {
	type CreateApplicationData,
	CreateApplicationSchema
} from "../schemas/create-application-schema"

export const CreateApplicationDialog = () => {
	const { mutateAsync: createApplication } = useCreateApplication()

	const form = useAppForm({
		defaultValues: {
			appId: "",
			appName: ""
		} as CreateApplicationData,
		validators: {
			onSubmit: CreateApplicationSchema
		},
		onSubmit: async ({ value }) => {
			await createApplication(value)
		}
	})

	return (
		<Dialog>
			<DialogTrigger asChild>
				<Button>
					<Plus /> Criar aplicação
				</Button>
			</DialogTrigger>
			<DialogContent>
				<DialogHeader>
					<DialogTitle>Crie uma nova Aplicação</DialogTitle>
					<DialogDescription>
						Adicione uma nova aplicação que vai usar Draft Auth para autenticação e autorização
					</DialogDescription>
				</DialogHeader>

				<form
					className="space-y-3"
					onSubmit={(e) => {
						e.preventDefault()
						e.stopPropagation()
						form.handleSubmit()
					}}
				>
					<form.AppField name="appId">
						{(field) => (
							<field.Fieldset>
								<field.LabelField>ID da Aplicação</field.LabelField>
								<field.TextField placeholder="Ex:. e-commerce-app" />
								<field.ErrorMessages />
							</field.Fieldset>
						)}
					</form.AppField>

					<form.AppField name="appName">
						{(field) => (
							<field.Fieldset>
								<field.LabelField>Nome da Aplicação</field.LabelField>
								<field.TextField placeholder="Ex:. E-Commerce App" />
								<field.ErrorMessages />
							</field.Fieldset>
						)}
					</form.AppField>

					<form.AppForm>
						<form.SubscribeButton>Criar</form.SubscribeButton>
					</form.AppForm>
				</form>
			</DialogContent>
		</Dialog>
	)
}
