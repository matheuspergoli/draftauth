import { api } from "@/libs/api"
import { useMutation } from "@tanstack/react-query"
import type { CreateApplicationData } from "../schemas/create-application-schema"

export const useCreateApplication = () => {
	return useMutation({
		mutationFn: async (data: CreateApplicationData) => {
			await api.manage.applications.$post({
				json: data
			})
		}
	})
}
