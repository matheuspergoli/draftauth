import { hmacAuthMiddleware } from "@/middlewares/hmac-middleware"
import { getUserAppAccessStatus, setUserAppAccessStatus } from "@/services/access-service"
import { getApiKeyDetailsForKeyId } from "@/services/api-key-service"
import {
	assignRoleToUser,
	getRoleDetailsByNameAndApp,
	revokeRoleFromUser
} from "@/services/role-service"
import { zValidator } from "@hono/zod-validator"
import { Hono } from "hono"
import { z } from "zod"

export const serviceRouter = new Hono()
	.use("*", hmacAuthMiddleware)

	.get("/users/:userId/access", async (c) => {
		const { userId } = c.req.param()
		const serviceKeyId = c.get("serviceKeyId")
		const apiKeyDetails = await getApiKeyDetailsForKeyId({ keyId: serviceKeyId })
		const userStatus = await getUserAppAccessStatus({ userId, appId: apiKeyDetails.appId })
		return c.json(userStatus)
	})

	.put(
		"/users/:userId/access",
		zValidator("json", z.object({ status: z.enum(["enabled", "disabled"]) })),
		async (c) => {
			const { userId } = c.req.param()
			const { status } = c.req.valid("json")
			const serviceKeyId = c.get("serviceKeyId")
			const apiKeyDetails = await getApiKeyDetailsForKeyId({ keyId: serviceKeyId })
			await setUserAppAccessStatus({ appId: apiKeyDetails.appId, userId, status })
			return c.body(null, 204)
		}
	)

	.post(
		"/roles/:userId/assign",
		zValidator("json", z.object({ roleName: z.string() })),
		async (c) => {
			const { userId } = c.req.param()
			const { roleName } = c.req.valid("json")
			const serviceKeyId = c.get("serviceKeyId")
			const apiKeyDetails = await getApiKeyDetailsForKeyId({ keyId: serviceKeyId })
			const roleDetails = await getRoleDetailsByNameAndApp({
				roleName,
				appId: apiKeyDetails.appId
			})
			await assignRoleToUser({ roleId: roleDetails.roleId, userId })
			return c.body(null, 200)
		}
	)

	.delete(
		"/users/:userId/revoke",
		zValidator("json", z.object({ roleName: z.string() })),
		async (c) => {
			const { userId } = c.req.param()
			const { roleName } = c.req.valid("json")
			const serviceKeyId = c.get("serviceKeyId")
			const apiKeyDetails = await getApiKeyDetailsForKeyId({ keyId: serviceKeyId })
			const roleDetails = await getRoleDetailsByNameAndApp({
				roleName,
				appId: apiKeyDetails.appId
			})
			await revokeRoleFromUser({ roleId: roleDetails.roleId, userId })
			return c.body(null, 200)
		}
	)
