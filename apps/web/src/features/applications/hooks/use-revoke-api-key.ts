import { api } from "@/libs/api"
import { useMutation } from "@tanstack/react-query"

export const useRevokeApiKey = () => {
	return useMutation({
		mutationFn: async ({ keyId }: { keyId: string }) => {
			await api.manage["api-keys"][":keyId"].$delete({
				param: {
					keyId
				}
			})
		}
	})
}
