import { useMutation } from "@tanstack/react-query"
import { api } from "@/libs/api"

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
