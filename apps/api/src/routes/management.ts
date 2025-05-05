import { adminMiddleware } from "@/middlewares/admin-middleware"
import {
	getUserAppAccessStatus,
	getUserAppAccessStatuses,
	setUserAppAccessStatus
} from "@/services/access-service"
import { generateApiKey, listApiKeysForApp, revokeApiKey } from "@/services/api-key-service"
import {
	addRedirectUri,
	createApplication,
	deleteApplication,
	deleteRedirectUri,
	getApplicationDetails,
	listApplicationsWithCounts,
	listRedirectUrisForApp
} from "@/services/application-service"
import { CONFIG_KEYS, getConfigValue } from "@/services/config-service"
import {
	assignRoleToUser,
	createRole,
	deleteRole,
	getUserAppRoles,
	getUserRolesForApp,
	listRolesForApp,
	revokeRoleFromUser,
	updateRole
} from "@/services/role-service"
import {
	getUserDetails,
	getUserGlobalStatus,
	listUsers,
	setUserGlobalStatus
} from "@/services/user-service"
import { zValidator } from "@hono/zod-validator"
import { Hono } from "hono"
import { HTTPException } from "hono/http-exception"
import { z } from "zod"

export const manageRouter = new Hono()
	.use("*", adminMiddleware)

	.get("/user", async (c) => {
		const ownerId = c.get("ownerId")
		const userDetails = await getUserDetails({ userId: ownerId })
		return c.json({ ...userDetails, isOwner: true })
	})

	.get("/users/:id", async (c) => {
		const requestedUserId = c.req.param("id")
		const userDetails = await getUserDetails({ userId: requestedUserId })
		return c.json(userDetails)
	})

	.get("/users/:id/status", async (c) => {
		const requestedUserId = c.req.param("id")
		const status = await getUserGlobalStatus({ userId: requestedUserId })
		return c.json({ userId: requestedUserId, status })
	})

	.get("/users/:id/applications-roles", async (c) => {
		const requestedUserId = c.req.param("id")
		const appRolesList = await getUserAppRoles({ userId: requestedUserId })
		return c.json(appRolesList)
	})

	.get("/users/:id/applications-access", async (c) => {
		const requestedUserId = c.req.param("id")
		const appAccessList = await getUserAppAccessStatuses({ userId: requestedUserId })
		return c.json(appAccessList)
	})

	.get(
		"/users/:id/roles",
		zValidator(
			"query",
			z.object({
				appId: z
					.string()
					.min(3)
					.max(50)
					.regex(/^[a-z0-9-]+$/i)
			})
		),
		async (c) => {
			const { appId } = c.req.valid("query")
			const requestedUserId = c.req.param("id")
			const roles = await getUserRolesForApp({ appId, userId: requestedUserId })
			return c.json({ userId: requestedUserId, appId, roles })
		}
	)

	.get(
		"/users/:id/access",
		zValidator(
			"query",
			z.object({
				appId: z
					.string()
					.min(3)
					.max(50)
					.regex(/^[a-z0-9-]+$/i)
			})
		),
		async (c) => {
			const { appId } = c.req.valid("query")
			const requestedUserId = c.req.param("id")
			const status = await getUserAppAccessStatus({ appId, userId: requestedUserId })
			return c.json({ userId: requestedUserId, appId, status })
		}
	)

	.get("/applications/:appId/redirect-uris", async (c) => {
		const appId = c.req.param("appId")
		const uris = await listRedirectUrisForApp({ appId })
		return c.json(uris)
	})

	.post(
		"/applications/:appId/redirect-uris",
		zValidator("json", z.object({ uri: z.string().url() })),
		async (c) => {
			const appId = c.req.param("appId")
			const { uri } = c.req.valid("json")
			await addRedirectUri({ appId, uri })
			return c.body(null, 201)
		}
	)

	.delete(
		"/applications/:appId/redirect-uris",
		zValidator("json", z.object({ uriId: z.string().uuid() })),
		async (c) => {
			const appId = c.req.param("appId")
			const { uriId } = c.req.valid("json")
			await deleteRedirectUri({ appId, uriId })
			return c.body(null, 204)
		}
	)

	.get("/users", async (c) => {
		const usersList = await listUsers()
		return c.json(usersList)
	})

	.put(
		"/users/:id/status",
		zValidator("json", z.object({ status: z.enum(["active", "inactive"]) })),
		async (c) => {
			const { status } = c.req.valid("json")
			const requestedUserId = c.req.param("id")
			await setUserGlobalStatus({ userId: requestedUserId, status })
			return c.json({ userId: requestedUserId, status })
		}
	)

	.get("/applications", async (c) => {
		const apps = await listApplicationsWithCounts()
		return c.json(apps)
	})

	.get("/applications/:appId", async (c) => {
		const appId = c.req.param("appId")
		const appDetails = await getApplicationDetails({ appId })
		return c.json(appDetails)
	})

	.post(
		"/applications",
		zValidator(
			"json",
			z.object({
				appId: z
					.string()
					.min(3)
					.max(50)
					.regex(/^[a-z0-9-]+$/i),
				appName: z.string().min(3).max(50)
			})
		),
		async (c) => {
			const data = c.req.valid("json")
			await createApplication(data)
			return c.body(null, 201)
		}
	)

	.delete("/:appId", async (c) => {
		const appId = c.req.param("appId")
		const coreAppId = await getConfigValue(CONFIG_KEYS.PRIMARY_MANAGEMENT_APP_ID)
		if (appId === coreAppId) {
			throw new HTTPException(409, { message: "Não é possível deletar a aplicação principal" })
		}
		await deleteApplication({ appId })
		return c.body(null, 204)
	})

	.get("/applications/:appId/roles", async (c) => {
		const appId = c.req.param("appId")
		const rolesList = await listRolesForApp({ appId })
		return c.json(rolesList)
	})

	.post(
		"/applications/:appId/roles",
		zValidator("json", z.object({ roleName: z.string().min(3).max(50) })),
		async (c) => {
			const appId = c.req.param("appId")
			const { roleName } = c.req.valid("json")
			await createRole({ appId, roleName: roleName })
			return c.body(null, 201)
		}
	)

	.put(
		"/applications/:appId/roles/:roleId",
		zValidator("json", z.object({ roleName: z.string().min(3).max(50) })),
		async (c) => {
			const appId = c.req.param("appId")
			const roleId = c.req.param("roleId")
			const { roleName } = c.req.valid("json")
			await updateRole({ appId, roleId, roleName: roleName })
			return c.body(null, 204)
		}
	)

	.delete("/roles/:roleId", async (c) => {
		const roleId = c.req.param("roleId")
		await deleteRole({ roleId })
		return c.body(null, 204)
	})

	.post(
		"/users/:userId/roles",
		zValidator("json", z.object({ roleId: z.string().uuid() })),
		async (c) => {
			const userId = c.req.param("userId")
			const { roleId } = c.req.valid("json")
			await assignRoleToUser({ userId, roleId })
			return c.body(null, 201)
		}
	)

	.delete("/users/:userId/roles/:roleId", async (c) => {
		const userId = c.req.param("userId")
		const roleId = c.req.param("roleId")
		await revokeRoleFromUser({ userId, roleId })
		return c.body(null, 204)
	})

	.put(
		"/users/:userId/access/:appId",
		zValidator("json", z.object({ status: z.enum(["enabled", "disabled"]) })),
		async (c) => {
			const appId = c.req.param("appId")
			const userId = c.req.param("userId")
			const { status } = c.req.valid("json")
			await setUserAppAccessStatus({ userId, appId, status })
			return c.json({ userId, appId, status })
		}
	)

	.get("/:appId/api-keys", async (c) => {
		const appId = c.req.param("appId")
		const keys = await listApiKeysForApp({ appId })
		return c.json(keys)
	})

	.post("/:appId/api-keys", async (c) => {
		const appId = c.req.param("appId")
		const apiKey = await generateApiKey({ appId })
		return c.json(apiKey, 201)
	})

	.delete("/api-keys/:keyId", async (c) => {
		const keyId = c.req.param("keyId")
		await revokeApiKey({ keyId })
		return c.body(null, 204)
	})
