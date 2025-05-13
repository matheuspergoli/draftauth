import { Button } from "@/shared/components/button"
import {
	Dialog,
	DialogContent,
	DialogHeader,
	DialogTitle,
	DialogTrigger
} from "@/shared/components/dialog"
import { useAppForm } from "@/shared/components/form"
import { useRouteContext } from "@tanstack/react-router"
import { useUpdateRole } from "../hooks/use-update-role"
import { type UpdateRoleData, UpdateRoleSchema } from "../schemas/update-role-schema"

export const UpdateRoleDialog = ({
	appId,
	roleId,
	roleName
}: { appId: string; roleName: string; roleId: string }) => {
	const { ability } = useRouteContext({ from: "/dashboard" })
	const { mutateAsync: updateRole } = useUpdateRole()

	const form = useAppForm({
		defaultValues: {
			roleName
		} as UpdateRoleData,
		validators: {
			onSubmit: UpdateRoleSchema
		},
		onSubmit: async ({ value }) => {
			await updateRole({ roleName: value.roleName, roleId, appId })
		}
	})

	return (
		<Dialog>
			<DialogTrigger asChild>
				<Button disabled={ability.cannot("edit_role", "Application")}>Gerenciar</Button>
			</DialogTrigger>
			<DialogContent>
				<DialogHeader>
					<DialogTitle>Modifique o cargo {roleName}</DialogTitle>
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
								<field.LabelField>Atualize o nome do cargo</field.LabelField>
								<field.TextField />
								<field.ErrorMessages />
							</field.Fieldset>
						)}
					</form.AppField>

					<form.AppForm>
						<form.SubscribeButton
							disabled={ability.cannot("edit_role", "Application")}
							className="mt-3"
						>
							Atualizar
						</form.SubscribeButton>
					</form.AppForm>
				</form>
			</DialogContent>
		</Dialog>
	)
}
