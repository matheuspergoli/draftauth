import { api } from "@/libs/api"
import { useMutation } from "@tanstack/react-query"

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
