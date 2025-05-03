import { api } from "@/libs/api"
import { useMutation } from "@tanstack/react-query"

export const useAssignRoleToUser = () => {
	return useMutation({
		mutationFn: async (data: { userId: string; roleId: string }) => {
			await api.manage.users[":userId"].roles.$post({
				param: { userId: data.userId },
				json: { roleId: data.roleId }
			})
		}
	})
}
