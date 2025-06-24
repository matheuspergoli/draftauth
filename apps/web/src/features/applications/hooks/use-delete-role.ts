import { useMutation } from "@tanstack/react-query"
import { api } from "@/libs/api"

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
