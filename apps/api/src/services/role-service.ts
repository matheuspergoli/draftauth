import { db } from "@/db/client"
import { applications, roles, userRoles, users } from "@/db/schema"
import { and, eq } from "drizzle-orm"
import { HTTPException } from "hono/http-exception"

export const listRolesForApp = async ({ appId }: { appId: string }) => {
	const requestedApp = await db
		.select()
		.from(applications)
		.where(eq(applications.appId, appId))
		.get()

	if (!requestedApp) {
		throw new HTTPException(404, {
			message: `Aplicação com AppID: ${appId} não foi encontrada`
		})
	}

	return await db
		.select({
			appId: roles.appId,
			roleId: roles.roleId,
			roleName: roles.roleName
		})
		.from(roles)
		.where(eq(roles.appId, requestedApp.appId))
		.orderBy(roles.roleName)
}

export const getRoleDetailsByNameAndApp = async ({
	roleName,
	appId
}: { roleName: string; appId: string }) => {
	const [requestedApp, requestedRole] = await Promise.all([
		db.query.applications.findFirst({
			where: eq(applications.appId, appId)
		}),
		db.query.roles.findFirst({
			where: and(eq(roles.roleName, roleName), eq(roles.appId, appId))
		})
	])

	if (!requestedApp) {
		throw new HTTPException(404, {
			message: `Aplicação com AppID: ${appId} não foi encontrada`
		})
	}

	if (!requestedRole) {
		throw new HTTPException(404, {
			message: `Cargo com nome: ${roleName} não foi encontrado`
		})
	}

	return requestedRole
}

export const createRole = async (data: {
	appId: string
	roleName: string
}) => {
	const [requestedApp, roleExists] = await Promise.all([
		db.query.applications.findFirst({
			where: eq(applications.appId, data.appId)
		}),
		db.query.roles.findFirst({
			where: eq(roles.roleName, data.roleName)
		})
	])

	if (roleExists) {
		throw new HTTPException(409, { message: `O cargo com nome ${data.roleName} já existe` })
	}

	if (!requestedApp) {
		throw new HTTPException(404, {
			message: `Aplicação com AppID: ${data.appId} não foi encontrada`
		})
	}

	return await db
		.insert(roles)
		.values({ appId: data.appId, roleName: data.roleName })
		.returning()
		.get()
}

export const updateRole = async (data: {
	appId: string
	roleId: string
	roleName: string
}) => {
	const [requestedApp, requestedRole] = await Promise.all([
		db.query.applications.findFirst({
			where: eq(applications.appId, data.appId)
		}),
		db.query.roles.findFirst({
			where: eq(roles.roleId, data.roleId)
		})
	])

	if (!requestedApp) {
		throw new HTTPException(404, {
			message: `Aplicação com AppID: ${data.appId} não foi encontrada`
		})
	}

	if (!requestedRole) {
		throw new HTTPException(404, {
			message: `Cargo com RoleID: ${data.roleId} não foi encontrado`
		})
	}

	await db
		.update(roles)
		.set({ roleName: data.roleName })
		.where(and(eq(roles.roleId, data.roleId), eq(roles.appId, data.appId)))
}

export const deleteRole = async ({ roleId }: { roleId: string }) => {
	const roleToDelete = await db
		.select({
			roleName: roles.roleName
		})
		.from(roles)
		.where(eq(roles.roleId, roleId))
		.get()

	if (!roleToDelete) {
		throw new HTTPException(404, {
			message: `Cargo com RoleID: ${roleId} não foi encontrado`
		})
	}

	await db.delete(roles).where(eq(roles.roleId, roleId))
}

export const assignRoleToUser = async ({
	userId,
	roleId
}: { userId: string; roleId: string }) => {
	const [requestedUser, requestedRole] = await Promise.all([
		db.query.users.findFirst({
			where: eq(users.userId, userId)
		}),
		db.query.roles.findFirst({
			where: eq(roles.roleId, roleId)
		})
	])

	if (!requestedRole) {
		throw new HTTPException(404, {
			message: `Cargo com RoleID: ${roleId} não foi encontrado`
		})
	}

	if (!requestedUser) {
		throw new HTTPException(404, { message: `Usuário com ID: ${userId} não foi encontrado` })
	}

	await db.insert(userRoles).values({ userId, roleId }).onConflictDoNothing()
}

export const revokeRoleFromUser = async ({
	userId,
	roleId
}: { userId: string; roleId: string }) => {
	const [requestedUser, requestedRole] = await Promise.all([
		db.query.users.findFirst({
			where: eq(users.userId, userId)
		}),
		db.query.roles.findFirst({
			where: eq(roles.roleId, roleId)
		})
	])

	if (!requestedRole) {
		throw new HTTPException(404, {
			message: `Cargo com RoleID: ${roleId} não foi encontrado`
		})
	}

	if (!requestedUser) {
		throw new HTTPException(404, { message: `Usuário com ID: ${userId} não foi encontrado` })
	}

	await db
		.delete(userRoles)
		.where(and(eq(userRoles.userId, userId), eq(userRoles.roleId, roleId)))
}

export const getRoleDetails = async ({ roleId }: { roleId: string }) => {
	const requestedRole = await db.query.roles.findFirst({
		where: eq(roles.roleId, roleId)
	})

	if (!requestedRole) {
		throw new HTTPException(404, {
			message: `Cargo com RoleID: ${roleId} não foi encontrado`
		})
	}

	return requestedRole
}

export const getUserRolesForApp = async ({
	appId,
	userId
}: {
	appId: string
	userId: string
}) => {
	const [requestedApp, requestedUser] = await Promise.all([
		db.query.applications.findFirst({
			where: eq(applications.appId, appId)
		}),
		db.query.users.findFirst({
			where: eq(users.userId, userId)
		})
	])

	if (!requestedApp) {
		throw new HTTPException(404, {
			message: `Aplicação com AppID: ${appId} não foi encontrada`
		})
	}

	if (!requestedUser) {
		throw new HTTPException(404, { message: `Usuário com ID: ${userId} não foi encontrado` })
	}

	return await db
		.select({ roleName: roles.roleName })
		.from(userRoles)
		.innerJoin(roles, eq(userRoles.roleId, roles.roleId))
		.where(and(eq(userRoles.userId, userId), eq(roles.appId, appId)))
		.orderBy(roles.roleName)
		.then((v) => v.map((a) => a.roleName))
}

export const getUserAppRoles = async ({ userId }: { userId: string }) => {
	const requestedUser = await db.select().from(users).where(eq(users.userId, userId)).get()

	if (!requestedUser) {
		throw new HTTPException(404, { message: `Usuário com ID: ${userId} não foi encontrado` })
	}

	const results = await db
		.select({
			appId: applications.appId,
			appName: applications.appName,
			roleId: roles.roleId,
			roleName: roles.roleName
		})
		.from(userRoles)
		.innerJoin(roles, eq(userRoles.roleId, roles.roleId))
		.innerJoin(applications, eq(roles.appId, applications.appId))
		.where(eq(userRoles.userId, userId))
		.orderBy(applications.appName, roles.roleName)

	const appRolesMap = new Map<
		string,
		{ roles: { roleId: string; roleName: string }[]; appId: string; appName: string }
	>()

	for (const row of results) {
		if (!appRolesMap.has(row.appId)) {
			appRolesMap.set(row.appId, {
				roles: [],
				appId: row.appId,
				appName: row.appName
			})
		}
		appRolesMap.get(row.appId)?.roles.push({
			roleId: row.roleId,
			roleName: row.roleName
		})
	}

	return Array.from(appRolesMap.values())
}
