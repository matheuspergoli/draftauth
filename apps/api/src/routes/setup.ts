import { dbClient } from "@/db/client"
import { env } from "@/environment/env"
import { setUserAppAccessStatus } from "@/services/access-service"
import { addRedirectUri, createApplication } from "@/services/application-service"
import { CONFIG_KEYS, isSetupComplete, setConfigValue } from "@/services/config-service"
import { TursoStorage } from "@draftauth/core/storage/turso"
import { zValidator } from "@hono/zod-validator"
import { Hono } from "hono"
import { HTTPException } from "hono/http-exception"
import { z } from "zod"

export const setupRouter = new Hono()
	.post(
		"/initialize",
		zValidator(
			"json",
			z.object({
				state: z.string().min(32),
				redirectURI: z.string().url(),
				appName: z.string().min(3).max(50)
			})
		),
		async (c) => {
			const appId = env.OWNER_APPLICATION_ID
			const { state, appName, redirectURI } = c.req.valid("json")

			const storage = TursoStorage(dbClient)
			const stateKey = ["setup_state", state]
			const stateData = (await storage.get(stateKey)) as { userId: string }
			await storage.remove(stateKey)

			if (!stateData || !stateData.userId) {
				throw new HTTPException(401, {
					message: "Sessão da configuração inválida ou expirada"
				})
			}

			const setupUserId = stateData.userId
			const setupComplete = await isSetupComplete()

			if (setupComplete) {
				throw new HTTPException(400, {
					message: "O sistema já foi inicializado e configurado"
				})
			}

			await createApplication({ appId, appName })

			await Promise.all([
				addRedirectUri({ appId, uri: redirectURI }),
				setConfigValue(CONFIG_KEYS.INITIAL_SETUP_COMPLETE, "true"),
				setConfigValue(CONFIG_KEYS.PRIMARY_MANAGEMENT_APP_ID, appId),
				setConfigValue(CONFIG_KEYS.SYSTEM_OWNER_USER_ID, setupUserId),
				setUserAppAccessStatus({ userId: setupUserId, appId, status: "enabled" })
			])

			return c.body(null, 201)
		}
	)
	.get("/status", async (c) => {
		const complete = await isSetupComplete()
		return c.json({ setupComplete: complete })
	})
