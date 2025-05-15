import { type AppNameActions, type AppSubjectTypeMappings, SYSTEM_ROLES } from "@/libs/ability"
import { authClient, subjects } from "@/libs/auth"
import { getUserAppAccessStatus } from "@/services/access-service"
import { CONFIG_KEYS, getConfigValue } from "@/services/config-service"
import { getUserRolesForApp } from "@/services/role-service"
import { getUserGlobalStatus } from "@/services/user-service"
import { type Ability, AbilityBuilder, type Rule } from "@draftauth/ability"
import { createMiddleware } from "hono/factory"
import { HTTPException } from "hono/http-exception"

export interface AdminEnv {
	Variables: {
		adminUserId: string
		ability: Ability<AppNameActions, AppSubjectTypeMappings>
		abilityRules: Rule<AppNameActions, AppSubjectTypeMappings>[]
	}
}

type DefinePermissionsFn = (
	abilityBuilder: AbilityBuilder<AppNameActions, AppSubjectTypeMappings>
) => void

const rolePermissionsMap: Record<string, DefinePermissionsFn> = {
	[SYSTEM_ROLES.SUPER_ADMIN_ROLE]: (ability) => {
		ability.can("access_admin_panel", "AdminPanel")
		ability.can(
			[
				"view_application",
				"create_application",
				"delete_application",
				"create_redirect_uri",
				"delete_redirect_uri",
				"create_api_key",
				"delete_api_key",
				"edit_role",
				"create_role",
				"delete_role"
			],
			"Application"
		)
		ability.can(
			[
				"view_user",
				"assign_role_to_user",
				"revoke_role_from_user",
				"edit_user_global_status",
				"edit_user_application_access"
			],
			"User"
		)
	},
	[SYSTEM_ROLES.APPLICATION_ADMINISTRATOR_ROLE]: (ability) => {
		ability.can("access_admin_panel", "AdminPanel")
		ability.can(
			["view_application", "create_redirect_uri", "create_api_key", "create_role"],
			"Application"
		)
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

	const managementAppId = await getConfigValue(CONFIG_KEYS.PRIMARY_MANAGEMENT_APP_ID)
	if (!managementAppId) {
		throw new HTTPException(500, {
			message: "Configuração crítica: Aplicação de gerenciamento principal não identificada."
		})
	}

	const currentAppStatus = await getUserAppAccessStatus({
		appId: managementAppId,
		userId: verifiedUser.id
	})

	if (currentAppStatus !== "enabled") {
		throw new HTTPException(403, {
			message: `Acesso negado: essa conta está ${currentAppStatus || "indisponível"}`
		})
	}

	const userRoles = await getUserRolesForApp({
		appId: managementAppId,
		userId: verifiedUser.id
	})

	const abilityBuilder = new AbilityBuilder<AppNameActions, AppSubjectTypeMappings>()

	for (const roleName of userRoles) {
		const definePermissions = rolePermissionsMap[roleName]
		if (definePermissions) {
			definePermissions(abilityBuilder)
		}
	}

	const ability = abilityBuilder.build()

	if (ability.cannot("access_admin_panel", "AdminPanel")) {
		throw new HTTPException(403, {
			message: "Acesso negado: Você não tem permissão para acessar a área administrativa."
		})
	}

	c.set("ability", ability)
	c.set("adminUserId", verifiedUser.id)
	c.set("abilityRules", abilityBuilder.rules)

	await next()
})
