import { SYSTEM_ROLES } from "@/libs/ability"
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
import { getAuditLogs } from "@/services/audit-log-service"
import { CONFIG_KEYS, getConfigValue } from "@/services/config-service"
import { getDashboardStats } from "@/services/dashboard-service"
import {
	assignRoleToUser,
	createRole,
	deleteRole,
	getRoleDetails,
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

	.get("/audit-logs", async (c) => {
		const logs = await getAuditLogs()
		return c.json(logs)
	})

	.get("/dashboard/stats", async (c) => {
		const stats = await getDashboardStats()
		return c.json(stats)
	})

	.get("/user", async (c) => {
		const rules = c.get("abilityRules")
		const adminId = c.get("adminUserId")
		const userDetails = await getUserDetails({ userId: adminId })
		return c.json({ ...userDetails, rules })
	})

	.get("/users/:id", async (c) => {
		const ability = c.get("ability")
		if (ability.cannot("view_user", "User")) {
			throw new HTTPException(403, {
				message: "Você não tem autorização suficiente para essa ação"
			})
		}
		const requestedUserId = c.req.param("id")
		const userDetails = await getUserDetails({ userId: requestedUserId })
		return c.json(userDetails)
	})

	.get("/users/:id/status", async (c) => {
		const ability = c.get("ability")
		if (ability.cannot("view_user", "User")) {
			throw new HTTPException(403, {
				message: "Você não tem autorização suficiente para essa ação"
			})
		}
		const requestedUserId = c.req.param("id")
		const status = await getUserGlobalStatus({ userId: requestedUserId })
		return c.json({ userId: requestedUserId, status })
	})

	.get("/users/:id/applications-roles", async (c) => {
		const ability = c.get("ability")
		if (ability.cannot("view_user", "User")) {
			throw new HTTPException(403, {
				message: "Você não tem autorização suficiente para essa ação"
			})
		}
		const requestedUserId = c.req.param("id")
		const appRolesList = await getUserAppRoles({ userId: requestedUserId })
		return c.json(appRolesList)
	})

	.get("/users/:id/applications-access", async (c) => {
		const ability = c.get("ability")
		if (ability.cannot("view_user", "User")) {
			throw new HTTPException(403, {
				message: "Você não tem autorização suficiente para essa ação"
			})
		}
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
			const ability = c.get("ability")
			if (ability.cannot("view_user", "User")) {
				throw new HTTPException(403, {
					message: "Você não tem autorização suficiente para essa ação"
				})
			}
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
			const ability = c.get("ability")
			if (ability.cannot("view_application", "Application")) {
				throw new HTTPException(403, {
					message: "Você não tem autorização suficiente para essa ação"
				})
			}
			const { appId } = c.req.valid("query")
			const requestedUserId = c.req.param("id")
			const status = await getUserAppAccessStatus({ appId, userId: requestedUserId })
			return c.json({ userId: requestedUserId, appId, status })
		}
	)

	.get("/applications/:appId/redirect-uris", async (c) => {
		const ability = c.get("ability")
		if (ability.cannot("view_application", "Application")) {
			throw new HTTPException(403, {
				message: "Você não tem autorização suficiente para essa ação"
			})
		}
		const appId = c.req.param("appId")
		const uris = await listRedirectUrisForApp({ appId })
		return c.json(uris)
	})

	.post(
		"/applications/:appId/redirect-uris",
		zValidator("json", z.object({ uri: z.string().url() })),
		async (c) => {
			const ability = c.get("ability")
			if (ability.cannot("create_redirect_uri", "Application")) {
				throw new HTTPException(403, {
					message: "Você não tem autorização para criar uma URI de Redirecionamento"
				})
			}
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
			const ability = c.get("ability")
			if (ability.cannot("delete_redirect_uri", "Application")) {
				throw new HTTPException(403, {
					message: "Você não tem autorização para excluir uma URI de Redirecionamento"
				})
			}
			const appId = c.req.param("appId")
			const { uriId } = c.req.valid("json")
			await deleteRedirectUri({ appId, uriId })
			return c.body(null, 204)
		}
	)

	.get("/users", async (c) => {
		const ability = c.get("ability")
		if (ability.cannot("view_user", "User")) {
			throw new HTTPException(403, {
				message: "Você não tem autorização suficiente para essa ação"
			})
		}
		const usersList = await listUsers()
		return c.json(usersList)
	})

	.put(
		"/users/:id/status",
		zValidator("json", z.object({ status: z.enum(["active", "inactive"]) })),
		async (c) => {
			const ability = c.get("ability")
			if (ability.cannot("edit_user_global_status", "User")) {
				throw new HTTPException(403, {
					message: "Você não tem autorização para modificar o status do usuário"
				})
			}
			const { status } = c.req.valid("json")
			const requestedUserId = c.req.param("id")
			await setUserGlobalStatus({ userId: requestedUserId, status })
			return c.json({ userId: requestedUserId, status })
		}
	)

	.get("/applications", async (c) => {
		const ability = c.get("ability")
		if (ability.cannot("view_application", "Application")) {
			throw new HTTPException(403, {
				message: "Você não tem autorização suficiente para essa ação"
			})
		}
		const apps = await listApplicationsWithCounts()
		return c.json(apps)
	})

	.get("/applications/:appId", async (c) => {
		const ability = c.get("ability")
		if (ability.cannot("view_application", "Application")) {
			throw new HTTPException(403, {
				message: "Você não tem autorização suficiente para essa ação"
			})
		}
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
			const ability = c.get("ability")
			if (ability.cannot("create_application", "Application")) {
				throw new HTTPException(403, {
					message: "Você não tem autorização para criar uma aplicação"
				})
			}
			const data = c.req.valid("json")
			await createApplication(data)
			return c.body(null, 201)
		}
	)

	.delete("/:appId", async (c) => {
		const ability = c.get("ability")
		if (ability.cannot("delete_application", "Application")) {
			throw new HTTPException(403, {
				message: "Você não tem autorização para excluir uma aplicação"
			})
		}
		const appId = c.req.param("appId")
		const coreAppId = await getConfigValue(CONFIG_KEYS.PRIMARY_MANAGEMENT_APP_ID)
		if (appId === coreAppId) {
			throw new HTTPException(409, { message: "Não é possível deletar a aplicação principal" })
		}
		await deleteApplication({ appId })
		return c.body(null, 204)
	})

	.get("/applications/:appId/roles", async (c) => {
		const ability = c.get("ability")
		if (ability.cannot("view_application", "Application")) {
			throw new HTTPException(403, {
				message: "Você não tem autorização suficiente para essa ação"
			})
		}
		const appId = c.req.param("appId")
		const rolesList = await listRolesForApp({ appId })
		return c.json(rolesList)
	})

	.post(
		"/applications/:appId/roles",
		zValidator("json", z.object({ roleName: z.string().min(3).max(50) })),
		async (c) => {
			const ability = c.get("ability")
			const appId = c.req.param("appId")
			const { roleName } = c.req.valid("json")
			if (ability.cannot("create_role", "Application")) {
				throw new HTTPException(403, {
					message: "Você não tem autorização para criar um cargo"
				})
			}
			const managementAppId = await getConfigValue(CONFIG_KEYS.PRIMARY_MANAGEMENT_APP_ID)
			if (appId === managementAppId && Object.values(SYSTEM_ROLES).includes(roleName)) {
				throw new HTTPException(409, {
					message: `O nome de cargo '${roleName}' é reservado para o sistema.`
				})
			}
			await createRole({ appId, roleName })
			return c.body(null, 201)
		}
	)

	.put(
		"/applications/:appId/roles/:roleId",
		zValidator("json", z.object({ roleName: z.string().min(3).max(50) })),
		async (c) => {
			const ability = c.get("ability")
			const appId = c.req.param("appId")
			const roleId = c.req.param("roleId")
			const { roleName } = c.req.valid("json")
			if (ability.cannot("edit_role", "Application")) {
				throw new HTTPException(403, {
					message: "Você não tem autorização para modificar um cargo"
				})
			}
			const managementAppId = await getConfigValue(CONFIG_KEYS.PRIMARY_MANAGEMENT_APP_ID)
			const roleDetails = await getRoleDetails({ roleId })
			if (
				roleDetails.appId === managementAppId &&
				Object.values(SYSTEM_ROLES).includes(roleDetails.roleName)
			) {
				throw new HTTPException(403, {
					message: "Não é possível modificar diretamente o nome de cargos críticos do sistema."
				})
			}
			await updateRole({ appId, roleId, roleName })
			return c.body(null, 204)
		}
	)

	.delete("/roles/:roleId", async (c) => {
		const ability = c.get("ability")
		const roleId = c.req.param("roleId")
		if (ability.cannot("delete_role", "Application")) {
			throw new HTTPException(403, {
				message: "Você não tem autorização para apagar um cargo"
			})
		}
		const roleToBeDeleted = await getRoleDetails({ roleId })
		const managementAppId = await getConfigValue(CONFIG_KEYS.PRIMARY_MANAGEMENT_APP_ID)
		if (
			roleToBeDeleted.appId === managementAppId &&
			Object.values(SYSTEM_ROLES).includes(roleToBeDeleted.roleName)
		) {
			throw new HTTPException(403, {
				message: "Não é possível apagar cargos críticos do sistema."
			})
		}
		await deleteRole({ roleId })
		return c.body(null, 204)
	})

	.post(
		"/users/:userId/roles",
		zValidator("json", z.object({ roleId: z.string().uuid() })),
		async (c) => {
			const ability = c.get("ability")
			if (ability.cannot("assign_role_to_user", "User")) {
				throw new HTTPException(403, {
					message: "Você não tem autorização para dar cargo ao usuário"
				})
			}
			const userId = c.req.param("userId")
			const { roleId } = c.req.valid("json")
			await assignRoleToUser({ userId, roleId })
			return c.body(null, 201)
		}
	)

	.delete("/users/:userId/roles/:roleId", async (c) => {
		const ability = c.get("ability")
		if (ability.cannot("revoke_role_from_user", "User")) {
			throw new HTTPException(403, {
				message: "Você não tem autorização para revogar cargo do usuário"
			})
		}
		const userId = c.req.param("userId")
		const roleId = c.req.param("roleId")
		await revokeRoleFromUser({ userId, roleId })
		return c.body(null, 204)
	})

	.put(
		"/users/:userId/access/:appId",
		zValidator("json", z.object({ status: z.enum(["enabled", "disabled"]) })),
		async (c) => {
			const ability = c.get("ability")
			if (ability.cannot("edit_user_application_access", "User")) {
				throw new HTTPException(403, {
					message: "Você não tem autorização para modificar o status do usuário"
				})
			}
			const appId = c.req.param("appId")
			const userId = c.req.param("userId")
			const { status } = c.req.valid("json")
			await setUserAppAccessStatus({ userId, appId, status })
			return c.json({ userId, appId, status })
		}
	)

	.get("/:appId/api-keys", async (c) => {
		const ability = c.get("ability")
		if (ability.cannot("view_application", "Application")) {
			throw new HTTPException(403, {
				message: "Você não tem autorização suficiente para essa ação"
			})
		}
		const appId = c.req.param("appId")
		const keys = await listApiKeysForApp({ appId })
		return c.json(keys)
	})

	.post("/:appId/api-keys", async (c) => {
		const ability = c.get("ability")
		if (ability.cannot("create_api_key", "Application")) {
			throw new HTTPException(403, {
				message: "Você não tem autorização para criar API Keys"
			})
		}
		const appId = c.req.param("appId")
		const apiKey = await generateApiKey({ appId })
		return c.json(apiKey, 201)
	})

	.delete("/api-keys/:keyId", async (c) => {
		const ability = c.get("ability")
		if (ability.cannot("delete_api_key", "Application")) {
			throw new HTTPException(403, {
				message: "Você não tem autorização para deletar API Keys"
			})
		}
		const keyId = c.req.param("keyId")
		await revokeApiKey({ keyId })
		return c.body(null, 204)
	})
