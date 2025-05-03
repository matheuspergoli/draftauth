import { api } from "@/libs/api"
import { useMutation } from "@tanstack/react-query"
import type { CreateRoleNameData } from "../schemas/create-role-name-schema"

export const useCreateRoleName = () => {
	return useMutation({
		mutationFn: async (data: CreateRoleNameData & { appId: string }) => {
			await api.manage.applications[":appId"].roles.$post({
				param: {
					appId: data.appId
				},
				json: { roleName: data.roleName }
			})
		}
	})
}
