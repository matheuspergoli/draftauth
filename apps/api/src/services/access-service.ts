import { db } from "@/db/client"
import { type AccessStatus, applications, userApplicationAccess, users } from "@/db/schema"
import { events } from "@/libs/events"
import { and, eq } from "drizzle-orm"
import { HTTPException } from "hono/http-exception"

export const setUserAppAccessStatus = async ({
	appId,
	status,
	userId
}: {
	appId: string
	userId: string
	status: AccessStatus
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

	events.emit("user.access.updated", {
		newStatus: status,
		userId,
		appId,
		details: {
			appId,
			userId,
			newStatus: status
		}
	})

	await db
		.insert(userApplicationAccess)
		.values({
			accessStatus: status,
			appId: requestedApp.appId,
			userId: requestedUser.userId
		})
		.onConflictDoUpdate({
			target: [userApplicationAccess.userId, userApplicationAccess.appId],
			set: {
				accessStatus: status
			}
		})
}

export const getUserAppAccessStatus = async ({
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

	const result = await db
		.select({
			status: userApplicationAccess.accessStatus
		})
		.from(userApplicationAccess)
		.where(
			and(
				eq(userApplicationAccess.appId, requestedApp.appId),
				eq(userApplicationAccess.userId, requestedUser.userId)
			)
		)
		.get()

	if (!result) {
		throw new HTTPException(404, {
			message: `Falha ao tentar recuperar o status da aplicação com AppID: ${appId} para o usuário com ID: ${userId}`
		})
	}

	return result.status
}

export const getUserAppAccessStatuses = async ({ userId }: { userId: string }) => {
	const requestedUser = await db.select().from(users).where(eq(users.userId, userId)).get()

	if (!requestedUser) {
		throw new HTTPException(404, { message: `Usuário com ID: ${userId} não foi encontrado` })
	}

	const results = await db
		.select({
			appId: applications.appId,
			appName: applications.appName,
			accessStatus: userApplicationAccess.accessStatus
		})
		.from(userApplicationAccess)
		.innerJoin(applications, eq(userApplicationAccess.appId, applications.appId))
		.where(eq(userApplicationAccess.userId, requestedUser.userId))

	return results.map((r) => ({
		appId: r.appId,
		appName: r.appName,
		accessStatus: r.accessStatus
	}))
}
