import { useMutation } from "@tanstack/react-query"
import { api } from "@/libs/api"

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
