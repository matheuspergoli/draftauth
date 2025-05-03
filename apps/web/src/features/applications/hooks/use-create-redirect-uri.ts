import { api } from "@/libs/api"
import { useMutation } from "@tanstack/react-query"
import type { CreateRedirectURIData } from "../schemas/create-redirect-uri-schema"

export const useCreateRedirectURI = () => {
	return useMutation({
		mutationFn: async (data: CreateRedirectURIData & { appId: string }) => {
			await api.manage.applications[":appId"]["redirect-uris"].$post({
				json: {
					uri: data.uri
				},
				param: {
					appId: data.appId
				}
			})
		}
	})
}
