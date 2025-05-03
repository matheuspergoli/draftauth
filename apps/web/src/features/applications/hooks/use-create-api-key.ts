import { api } from "@/libs/api"
import { useMutation } from "@tanstack/react-query"

export const useCreateApiKey = () => {
	return useMutation({
		mutationFn: async ({ appId }: { appId: string }) => {
			const response = await api.manage[":appId"]["api-keys"].$post({
				param: {
					appId
				}
			})

			return await response.json()
		}
	})
}
