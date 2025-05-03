import { z } from "zod"

export const UpdateRoleSchema = z.object({
	roleName: z
		.string()
		.min(3, "Nome do cargo deve ter no mínimo 3 caracteres")
		.max(50, "Nome do cargo deve ter no máximo 50 caracteres")
})

export type UpdateRoleData = z.infer<typeof UpdateRoleSchema>
