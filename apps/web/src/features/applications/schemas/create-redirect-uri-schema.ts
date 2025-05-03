import { z } from "zod"

export const CreateRedirectURISchema = z.object({
	uri: z.string().url("URI de redirecionamento deve ser uma URL válida")
})

export type CreateRedirectURIData = z.infer<typeof CreateRedirectURISchema>
