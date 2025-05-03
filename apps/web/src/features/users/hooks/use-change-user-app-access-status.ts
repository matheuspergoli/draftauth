import { api } from "@/libs/api"
import { useMutation } from "@tanstack/react-query"

export const useChangeUserAppAccessStatus = () => {
	return useMutation({
		mutationFn: async (data: { userId: string; appId: string; checked: boolean }) => {
			await api.manage.users[":userId"].access[":appId"].$put({
				json: { status: data.checked ? "enabled" : "disabled" },
				param: { appId: data.appId, userId: data.userId }
			})
		}
	})
}
