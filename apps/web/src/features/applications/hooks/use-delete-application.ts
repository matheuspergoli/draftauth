import { useMutation } from "@tanstack/react-query"
import { api } from "@/libs/api"

export const useDeleteApplication = () => {
	return useMutation({
		mutationFn: async (data: { appId: string }) => {
			await api.manage[":appId"].$delete({
				param: {
					appId: data.appId
				}
			})
		}
	})
}
