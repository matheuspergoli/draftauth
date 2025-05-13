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
import {
	Table,
	TableBody,
	TableCell,
	TableHead,
	TableHeader,
	TableRow
} from "@/shared/components/table"
import { applicationQueryOptions, applicationRolesQueryOptions } from "@/shared/queries"
import { useSuspenseQuery } from "@tanstack/react-query"
import { useParams, useRouteContext } from "@tanstack/react-router"
import { Plus, Trash } from "lucide-react"
import { useCreateRoleName } from "../hooks/use-create-role-name"
import { useDeleteRole } from "../hooks/use-delete-role"
import {
	type CreateRoleNameData,
	CreateRoleNameSchema
} from "../schemas/create-role-name-schema"
import { UpdateRoleDialog } from "./update-role-dialog"

export const ApplicationRoles = () => {
	const { ability } = useRouteContext({ from: "/dashboard" })
	const { appId } = useParams({ from: "/dashboard/applications/$appId" })

	const { mutateAsync: createRoleName } = useCreateRoleName()
	const { mutateAsync: deleteRole, isPending } = useDeleteRole()
	const { data } = useSuspenseQuery(applicationRolesQueryOptions(appId))
	const { data: application } = useSuspenseQuery(applicationQueryOptions(appId))

	const form = useAppForm({
		defaultValues: {
			roleName: ""
		} as CreateRoleNameData,
		validators: {
			onSubmit: CreateRoleNameSchema
		},
		onSubmit: async ({ value }) => {
			await createRoleName({ appId, roleName: value.roleName })
		}
	})

	return (
		<Card>
			<CardHeader className="flex justify-between">
				<div>
					<CardTitle>Cargos da Aplicação</CardTitle>
					<CardDescription>Cargos disponíveis na aplicação</CardDescription>
				</div>

				<Dialog>
					<DialogTrigger asChild>
						<Button disabled={ability.cannot("create_role", "Application")}>
							<Plus /> Criar novo cargo
						</Button>
					</DialogTrigger>
					<DialogContent>
						<DialogHeader>
							<DialogTitle>Crie um novo cargo para {application.appName}</DialogTitle>
							<DialogDescription>
								Cargos definem o que um usuário pode fazer na aplicação.
							</DialogDescription>
						</DialogHeader>

						<form
							onSubmit={(e) => {
								e.preventDefault()
								e.stopPropagation()
								form.handleSubmit()
							}}
						>
							<form.AppField name="roleName">
								{(field) => (
									<field.Fieldset>
										<field.LabelField>Escolha um nome para o cargo</field.LabelField>
										<field.TextField placeholder="Ex.: admin, editor" />
										<field.ErrorMessages />
									</field.Fieldset>
								)}
							</form.AppField>

							<form.AppForm>
								<form.SubscribeButton
									disabled={ability.cannot("create_role", "Application")}
									className="mt-3"
								>
									Criar cargo
								</form.SubscribeButton>
							</form.AppForm>
						</form>
					</DialogContent>
				</Dialog>
			</CardHeader>
			<CardContent>
				<Table>
					<TableHeader>
						<TableRow>
							<TableHead>Cargo</TableHead>
							<TableHead className="text-right">Modificar cargo</TableHead>
						</TableRow>
					</TableHeader>
					<TableBody>
						{data.map((values) => (
							<TableRow key={values.roleId}>
								<TableCell className="font-medium">{values.roleName}</TableCell>
								<TableCell className="gap-3 flex items-center justify-end">
									<UpdateRoleDialog
										appId={values.appId}
										roleId={values.roleId}
										roleName={values.roleName}
									/>

									<AlertDialog>
										<AlertDialogTrigger asChild>
											<Button
												disabled={ability.cannot("delete_role", "Application")}
												variant="destructive"
											>
												<Trash />
											</Button>
										</AlertDialogTrigger>
										<AlertDialogContent>
											<AlertDialogHeader>
												<AlertDialogTitle>Tem absoluta certeza disso?</AlertDialogTitle>
												<AlertDialogDescription>
													Essa ação não pode ser desfeita e irá apagar este cargo!
												</AlertDialogDescription>
											</AlertDialogHeader>
											<AlertDialogFooter>
												<AlertDialogCancel>Cancelar</AlertDialogCancel>
												<AlertDialogAction
													asChild
													disabled={ability.cannot("delete_role", "Application")}
													onClick={async () => await deleteRole({ roleId: values.roleId })}
												>
													<Button mode="loading" isLoading={isPending}>
														Apagar
													</Button>
												</AlertDialogAction>
											</AlertDialogFooter>
										</AlertDialogContent>
									</AlertDialog>
								</TableCell>
							</TableRow>
						))}
					</TableBody>
				</Table>
			</CardContent>
		</Card>
	)
}
