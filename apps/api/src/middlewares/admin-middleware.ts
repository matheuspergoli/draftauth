import { authClient, subjects } from "@/libs/auth"
import { CONFIG_KEYS, getConfigValue } from "@/services/config-service"
import { getUserGlobalStatus } from "@/services/user-service"
import { createMiddleware } from "hono/factory"
import { HTTPException } from "hono/http-exception"

export interface AdminEnv {
	Variables: {
		ownerId: string
	}
}

export const adminMiddleware = createMiddleware<AdminEnv>(async (c, next) => {
	const authHeader = c.req.header("Authorization")
	if (!authHeader) {
		throw new HTTPException(401, { message: "Header de autorização obrigatório" })
	}

	const parts = authHeader.split(" ")
	if (parts.length !== 2 || parts[0]?.toLowerCase() !== "bearer") {
		throw new HTTPException(401, { message: "Formato do token inválido" })
	}

	const token = parts[1]
	if (!token) {
		throw new HTTPException(401, {
			message: "Verificação do token falhou: Token não está presente"
		})
	}

	const verified = await authClient.verify(subjects, token)

	if (verified.err) {
		throw new HTTPException(401, {
			message: `Verificação do token falhou: ${verified.err.name}`
		})
	}

	const verifiedUser = verified.subject.properties

	const currentStatus = await getUserGlobalStatus({ userId: verifiedUser.id })

	if (!currentStatus || currentStatus !== "active") {
		throw new HTTPException(403, {
			message: `Acesso negado: essa conta está ${currentStatus || "indisponível"}`
		})
	}

	const [ownerId, appId] = await Promise.all([
		getConfigValue(CONFIG_KEYS.SYSTEM_OWNER_USER_ID),
		getConfigValue(CONFIG_KEYS.PRIMARY_MANAGEMENT_APP_ID)
	])

	if (!appId || !ownerId) {
		throw new HTTPException(400, {
			message: "Acesso negado: Aplicação principal ou proprietário não foram identificados"
		})
	}

	if (verifiedUser.id !== ownerId) {
		throw new HTTPException(403, {
			message: "Acesso negado: tentativa de acesso de não proprietário"
		})
	}

	c.set("ownerId", ownerId)

	await next()
})
