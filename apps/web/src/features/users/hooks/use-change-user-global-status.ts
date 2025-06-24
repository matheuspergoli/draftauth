import { useMutation } from "@tanstack/react-query"
import { api } from "@/libs/api"

export const useChangeUserGlobalStatus = () => {
	return useMutation({
		mutationFn: async (data: { userId: string; status: "active" | "inactive" }) => {
			await api.manage.users[":id"].status.$put({
				param: { id: data.userId },
				json: { status: data.status }
			})
		}
	})
}
