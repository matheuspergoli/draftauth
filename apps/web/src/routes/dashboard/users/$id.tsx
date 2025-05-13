import { useAssignRoleToUser } from "@/features/users/hooks/use-assign-role-to-user"
import { useChangeUserAppAccessStatus } from "@/features/users/hooks/use-change-user-app-access-status"
import { useChangeUserGlobalStatus } from "@/features/users/hooks/use-change-user-global-status"
import { useRevokeUserRole } from "@/features/users/hooks/use-revoke-user-role"
import { run } from "@/libs/utils"
import { Badge } from "@/shared/components/badge"
import { Button } from "@/shared/components/button"
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
import { PageTitle } from "@/shared/components/page-title"
import {
	Select,
	SelectContent,
	SelectGroup,
	SelectItem,
	SelectLabel,
	SelectTrigger,
	SelectValue
} from "@/shared/components/select"
import { Switch } from "@/shared/components/switch"
import {
	Table,
	TableBody,
	TableCell,
	TableHead,
	TableHeader,
	TableRow
} from "@/shared/components/table"
import {
	applicationRolesQueryOptions,
	applicationsQueryOptions,
	userApplicationsAccessQueryOptions,
	userApplicationsRolesQueryOptions,
	userQueryOptions
} from "@/shared/queries"
import { useQuery, useSuspenseQuery } from "@tanstack/react-query"
import { createFileRoute, useRouteContext } from "@tanstack/react-router"
import React from "react"

export const Route = createFileRoute("/dashboard/users/$id")({
	component: RouteComponent,
	loader: async ({ context, params }) => {
		await Promise.all([
			context.queryClient.prefetchQuery(applicationsQueryOptions),
			context.queryClient.prefetchQuery(userQueryOptions(params.id)),
			context.queryClient.prefetchQuery(userApplicationsRolesQueryOptions(params.id)),
			context.queryClient.prefetchQuery(userApplicationsAccessQueryOptions(params.id))
		])
	}
})

type AccessStatus = "enabled" | "disabled"

function RouteComponent() {
	const params = Route.useParams()
	const { ability } = useRouteContext({ from: "/dashboard" })
	const { mutateAsync: revokeUserRole } = useRevokeUserRole()
	const { mutateAsync: assignRoleToUser } = useAssignRoleToUser()
	const { mutateAsync: changeUserGlobalStatus } = useChangeUserGlobalStatus()
	const { mutateAsync: changeUserAppAccessStatus } = useChangeUserAppAccessStatus()

	const [currentAppId, setCurrentAppId] = React.useState("")

	const applicationRoles = useQuery(applicationRolesQueryOptions(currentAppId))

	const user = useSuspenseQuery(userQueryOptions(params.id))
	const applications = useSuspenseQuery(applicationsQueryOptions)
	const applicationsRoles = useSuspenseQuery(userApplicationsRolesQueryOptions(params.id))
	const applicationsAccess = useSuspenseQuery(userApplicationsAccessQueryOptions(params.id))

	const explicitStatusMap = React.useMemo(() => {
		const map = new Map<string, AccessStatus>()
		if (applicationsAccess.data) {
			for (const access of applicationsAccess.data) {
				map.set(access.appId, access.accessStatus)
			}
		}
		return map
	}, [applicationsAccess.data])

	const statusForm = useAppForm({
		defaultValues: {
			status: user.data.status
		},
		onSubmit: async ({ value }) => {
			await changeUserGlobalStatus({ userId: params.id, status: value.status })
		}
	})

	const rolesForm = useAppForm({
		defaultValues: {
			roleId: ""
		},
		onSubmit: async ({ value }) => {
			await assignRoleToUser({ roleId: value.roleId, userId: params.id })
		}
	})

	const renderRoles = () => {
		const roles = applicationRoles.data
		const rolesMap = roles?.map((value) => ({
			label: value.roleName,
			value: value.roleId
		}))

		return rolesMap ?? []
	}

	return (
		<main>
			<PageTitle>Detalhes do Usuário</PageTitle>

			<section className="space-y-3">
				<Card>
					<CardHeader>
						<CardTitle>Informações do Usuário</CardTitle>
						<CardDescription>Informações básicas do usuário</CardDescription>
					</CardHeader>
					<CardContent className="flex [&>*]:flex-1 gap-5">
						<fieldset className="space-y-1">
							<Label>User ID</Label>
							<Input value={user.data.userId} disabled />
						</fieldset>

						<fieldset className="space-y-1">
							<Label>Email</Label>
							<Input value={user.data.email} disabled />
						</fieldset>

						<form
							onChange={(e) => {
								e.preventDefault()
								e.stopPropagation()
								statusForm.handleSubmit()
							}}
						>
							<statusForm.AppField name="status">
								{(field) => (
									<field.Fieldset>
										<field.LabelField>Status</field.LabelField>
										<field.SelectField
											label="Status"
											disabled={ability.cannot("edit_user_global_status", "User")}
											placeholder="Status global do usuário"
											values={[
												{ label: "Ativo", value: "active" },
												{ label: "Inativo", value: "inactive" }
											]}
										/>
									</field.Fieldset>
								)}
							</statusForm.AppField>
						</form>
					</CardContent>
				</Card>

				<Card>
					<CardHeader>
						<CardTitle>Gerenciamento de Cargos</CardTitle>
						<CardDescription>
							Gerencia os cargos do usuário para diferentes aplicações
						</CardDescription>
					</CardHeader>
					<CardContent className="space-y-10">
						<form
							className="flex items-center [&>*]:flex-1 gap-5"
							onSubmit={(e) => {
								e.preventDefault()
								e.stopPropagation()
								rolesForm.handleSubmit()
							}}
						>
							<fieldset className="space-y-1">
								<Label>Selecionar Aplicação</Label>
								<Select
									disabled={ability.cannot("assign_role_to_user", "User")}
									defaultValue={currentAppId}
									onValueChange={(value) => {
										setCurrentAppId(value)
									}}
								>
									<SelectTrigger className="w-full">
										<SelectValue placeholder="Seleciona a aplicação" />
									</SelectTrigger>
									<SelectContent>
										<SelectGroup>
											<SelectLabel>Aplicações</SelectLabel>
											{applications.data.map((value) => (
												<SelectItem key={value.appId} value={value.appId}>
													{value.appName}
												</SelectItem>
											))}
										</SelectGroup>
									</SelectContent>
								</Select>
							</fieldset>

							<rolesForm.AppField name="roleId">
								{(field) => (
									<field.Fieldset>
										<field.LabelField>Selecionar Cargo</field.LabelField>
										<field.SelectField
											label="Cargos"
											disabled={ability.cannot("assign_role_to_user", "User")}
											placeholder="Selecione o cargo"
											values={renderRoles()}
										/>
									</field.Fieldset>
								)}
							</rolesForm.AppField>

							<rolesForm.AppForm>
								<rolesForm.SubscribeButton
									disabled={ability.cannot("assign_role_to_user", "User")}
									className="self-end"
								>
									Adicionar cargo
								</rolesForm.SubscribeButton>
							</rolesForm.AppForm>
						</form>

						<Table>
							<TableHeader>
								<TableRow>
									<TableHead>Aplicação</TableHead>
									<TableHead>Cargo Atribuído</TableHead>
									<TableHead className="text-right">Ações</TableHead>
								</TableRow>
							</TableHeader>
							<TableBody>
								{applicationsRoles.data && applicationsRoles.data.length > 0 ? (
									applicationsRoles.data.flatMap((appInfo) =>
										appInfo.roles.map((role) => (
											<TableRow key={`${appInfo.appId}-${role.roleId}`}>
												<TableCell className="font-medium">{appInfo.appName}</TableCell>
												<TableCell>
													<Badge variant="secondary">{role.roleName}</Badge>
												</TableCell>
												<TableCell className="text-right">
													<Button
														variant="destructive"
														size="sm"
														disabled={ability.cannot("revoke_role_from_user", "User")}
														onClick={async () =>
															await revokeUserRole({
																roleId: role.roleId,
																userId: params.id
															})
														}
													>
														Revogar
													</Button>
												</TableCell>
											</TableRow>
										))
									)
								) : (
									<TableRow>
										<TableCell colSpan={3} className="text-center">
											Usuário não possui cargos atribuídos.
										</TableCell>
									</TableRow>
								)}
							</TableBody>
						</Table>
					</CardContent>
				</Card>

				<Card>
					<CardHeader>
						<CardTitle>Acesso em Aplicações</CardTitle>
						<CardDescription>Controle acesso em cada aplicação</CardDescription>
					</CardHeader>
					<CardContent>
						<Table>
							<TableHeader>
								<TableRow>
									<TableHead>Aplicação</TableHead>
									<TableHead>Status</TableHead>
									<TableHead className="text-right">Modificar acesso</TableHead>
								</TableRow>
							</TableHeader>
							<TableBody>
								{applications.data.map((values) => {
									const explicitStatus = explicitStatusMap.get(values.appId)
									const currentAccessStatus = explicitStatus ?? "default"
									const isCurrentlyEnabled = currentAccessStatus !== "disabled"

									return (
										<TableRow key={values.appId}>
											<TableCell className="font-medium">{values.appName}</TableCell>
											<TableCell>
												{run(() => {
													if (explicitStatus === "enabled") {
														return <Badge>Habilitado</Badge>
													}

													if (explicitStatus === "disabled") {
														return <Badge variant="destructive">Desabilitado</Badge>
													}

													return <Badge variant="outline">Padrão (Permitido)</Badge>
												})}
											</TableCell>
											<TableCell className="text-right">
												<Switch
													disabled={ability.cannot("edit_user_application_access", "User")}
													defaultChecked={isCurrentlyEnabled}
													onCheckedChange={async (checked) => {
														await changeUserAppAccessStatus({
															checked,
															userId: params.id,
															appId: values.appId
														})
													}}
												/>
											</TableCell>
										</TableRow>
									)
								})}
							</TableBody>
						</Table>
					</CardContent>
				</Card>
			</section>
		</main>
	)
}
