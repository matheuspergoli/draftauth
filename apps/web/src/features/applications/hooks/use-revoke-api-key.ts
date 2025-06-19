import { useMutation } from "@tanstack/react-query"
import { api } from "@/libs/api"

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
