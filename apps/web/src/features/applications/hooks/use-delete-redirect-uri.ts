import { api } from "@/libs/api"
import { useMutation } from "@tanstack/react-query"

export const useDeleteRedirectURI = () => {
	return useMutation({
		mutationFn: async (data: { appId: string; uriId: string }) => {
			await api.manage.applications[":appId"]["redirect-uris"].$delete({
				param: {
					appId: data.appId
				},
				json: {
					uriId: data.uriId
				}
			})
		}
	})
}
