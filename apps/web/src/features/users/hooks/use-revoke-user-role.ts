import { api } from "@/libs/api"
import { useMutation } from "@tanstack/react-query"

export const useRevokeUserRole = () => {
	return useMutation({
		mutationFn: async (data: { userId: string; roleId: string }) => {
			await api.manage.users[":userId"].roles[":roleId"].$delete({
				param: {
					userId: data.userId,
					roleId: data.roleId
				}
			})
		}
	})
}
