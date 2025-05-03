import { api } from "@/libs/api"
import { useMutation } from "@tanstack/react-query"

export const useDeleteRole = () => {
	return useMutation({
		mutationFn: async (data: { roleId: string }) => {
			await api.manage.roles[":roleId"].$delete({
				param: {
					roleId: data.roleId
				}
			})
		}
	})
}
