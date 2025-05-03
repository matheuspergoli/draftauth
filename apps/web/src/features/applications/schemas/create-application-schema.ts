import { z } from "zod"

export const CreateApplicationSchema = z.object({
	appId: z
		.string()
		.min(3, "ID da aplicação deve ter no mínimo 3 caracteres")
		.max(50, "ID da aplicação deve ter no máximo 50 caracteres")
		.regex(
			/^[a-z0-9-]+$/i,
			"ID da aplicação deve conter apenas letras, números e hífens, sem espaços ou caracteres especiais"
		),
	appName: z
		.string()
		.min(3, "Nome da aplicação deve ter no mínimo 3 caracteres")
		.max(50, "Nome da aplicação deve ter no máximo 50 caracteres")
})

export type CreateApplicationData = z.infer<typeof CreateApplicationSchema>
