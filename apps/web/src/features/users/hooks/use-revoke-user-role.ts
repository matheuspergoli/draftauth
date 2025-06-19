import { useMutation } from "@tanstack/react-query"
import { api } from "@/libs/api"

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
