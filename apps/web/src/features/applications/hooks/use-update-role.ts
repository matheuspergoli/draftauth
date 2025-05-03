import { api } from "@/libs/api"
import { useMutation } from "@tanstack/react-query"

export const useUpdateRole = () => {
	return useMutation({
		mutationFn: async (data: { roleId: string; appId: string; roleName: string }) => {
			await api.manage.applications[":appId"].roles[":roleId"].$put({
				param: {
					appId: data.appId,
					roleId: data.roleId
				},
				json: {
					roleName: data.roleName
				}
			})
		}
	})
}
