import {
	AlertDialog,
	AlertDialogAction,
	AlertDialogCancel,
	AlertDialogContent,
	AlertDialogDescription,
	AlertDialogFooter,
	AlertDialogHeader,
	AlertDialogTitle,
	AlertDialogTrigger
} from "@/shared/components/alert-dialog"
import { Button } from "@/shared/components/button"
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle
} from "@/shared/components/card"
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogHeader,
	DialogTitle,
	DialogTrigger
} from "@/shared/components/dialog"
import { useAppForm } from "@/shared/components/form"
import { applicationRedirectUrisQueryOptions } from "@/shared/queries"
import { useSuspenseQuery } from "@tanstack/react-query"
import { useParams, useRouteContext } from "@tanstack/react-router"
import { Plus, Trash } from "lucide-react"
import { useCreateRedirectURI } from "../hooks/use-create-redirect-uri"
import { useDeleteRedirectURI } from "../hooks/use-delete-redirect-uri"
import {
	type CreateRedirectURIData,
	CreateRedirectURISchema
} from "../schemas/create-redirect-uri-schema"

export const ApplicationRedirectUris = () => {
	const { ability } = useRouteContext({ from: "/dashboard" })
	const { appId } = useParams({ from: "/dashboard/applications/$appId" })
	const { data } = useSuspenseQuery(applicationRedirectUrisQueryOptions(appId))

	const { mutateAsync: createRedirectURI } = useCreateRedirectURI()
	const { mutateAsync: deleteRedirectURI, isPending } = useDeleteRedirectURI()

	const form = useAppForm({
		defaultValues: {
			uri: ""
		} as CreateRedirectURIData,
		validators: {
			onSubmit: CreateRedirectURISchema
		},
		onSubmit: async ({ value }) => {
			await createRedirectURI({ uri: value.uri, appId })
		}
	})

	return (
		<Card>
			<CardHeader className="flex justify-between">
				<div>
					<CardTitle>URIs de Redirecionamento</CardTitle>
					<CardDescription>
						Configure as URIs de redirecionamento da aplicação durante o fluxo autenticação
					</CardDescription>
				</div>

				<Dialog>
					<DialogTrigger asChild>
						<Button disabled={ability.cannot("create_redirect_uri", "Application")}>
							<Plus /> Criar URI
						</Button>
					</DialogTrigger>
					<DialogContent>
						<DialogHeader>
							<DialogTitle>Crie uma nova URI de Redirecionamento</DialogTitle>
							<DialogDescription>
								Adicione uma nova URI para o processo de autenticação da aplicação
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
							<form.AppField name="uri">
								{(field) => (
									<field.Fieldset>
										<field.LabelField>URI de Redirecionamento</field.LabelField>
										<field.TextField placeholder="Ex:. https://my-app.com" />
										<field.ErrorMessages />
									</field.Fieldset>
								)}
							</form.AppField>

							<form.AppForm>
								<form.SubscribeButton
									disabled={ability.cannot("create_redirect_uri", "Application")}
								>
									Criar
								</form.SubscribeButton>
							</form.AppForm>
						</form>
					</DialogContent>
				</Dialog>
			</CardHeader>
			<CardContent>
				<div className="space-y-2">
					{data.map((uri) => (
						<div
							key={uri.uriId}
							className="flex items-center justify-between p-2 rounded-md border"
						>
							<span className="font-mono text-sm">{uri.uri}</span>

							<AlertDialog>
								<AlertDialogTrigger asChild>
									<Button
										disabled={ability.cannot("delete_redirect_uri", "Application")}
										variant="destructive"
									>
										<Trash />
									</Button>
								</AlertDialogTrigger>
								<AlertDialogContent>
									<AlertDialogHeader>
										<AlertDialogTitle>Tem absoluta certeza disso?</AlertDialogTitle>
										<AlertDialogDescription>
											Essa ação não pode ser desfeita e irá apagar permanentemente essa URI
										</AlertDialogDescription>
									</AlertDialogHeader>
									<AlertDialogFooter>
										<AlertDialogCancel>Cancelar</AlertDialogCancel>
										<AlertDialogAction
											asChild
											disabled={ability.cannot("delete_redirect_uri", "Application")}
											onClick={async () => {
												await deleteRedirectURI({ uriId: uri.uriId, appId })
											}}
										>
											<Button mode="loading" isLoading={isPending}>
												Apagar
											</Button>
										</AlertDialogAction>
									</AlertDialogFooter>
								</AlertDialogContent>
							</AlertDialog>
						</div>
					))}
				</div>
			</CardContent>
		</Card>
	)
}
