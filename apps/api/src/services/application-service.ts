import { db } from "@/db/client"
import {
	applicationRedirectUris,
	applications,
	roles,
	userApplicationAccess
} from "@/db/schema"
import { and, eq, sql } from "drizzle-orm"
import { HTTPException } from "hono/http-exception"

export const deleteApplication = async ({ appId }: { appId: string }) => {
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

	await db.delete(applications).where(eq(applications.appId, appId))
}

export const listRedirectUrisForApp = async ({ appId }: { appId: string }) => {
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
			uriId: applicationRedirectUris.uriId,
			uri: applicationRedirectUris.uri
		})
		.from(applicationRedirectUris)
		.where(eq(applicationRedirectUris.appId, appId))
		.orderBy(applicationRedirectUris.uri)
}

export const addRedirectUri = async ({ appId, uri }: { appId: string; uri: string }) => {
	const requestedApp = await db
		.select()
		.from(applications)
		.where(eq(applications.appId, appId))

	if (!requestedApp) {
		throw new HTTPException(404, {
			message: `Aplicação com AppID: ${appId} não foi encontrada`
		})
	}

	await db.insert(applicationRedirectUris).values({ appId, uri }).returning().get()
}

export const deleteRedirectUri = async ({
	uriId,
	appId
}: { uriId: string; appId: string }) => {
	const [requestedApp, requestedURI] = await Promise.all([
		db.query.applications.findFirst({
			where: eq(applications.appId, appId)
		}),
		db.query.applicationRedirectUris.findFirst({
			where: eq(applicationRedirectUris.uriId, uriId)
		})
	])

	if (!requestedApp) {
		throw new HTTPException(404, {
			message: `Aplicação com AppID: ${appId} não foi encontrada`
		})
	}

	if (!requestedURI) {
		throw new HTTPException(404, {
			message: `RedirectURI com URI ID: ${uriId} não foi encontrada`
		})
	}

	await db
		.delete(applicationRedirectUris)
		.where(
			and(eq(applicationRedirectUris.uriId, uriId), eq(applicationRedirectUris.appId, appId))
		)
}

export const isValidApplicationClient = async ({
	clientId,
	redirectUri
}: {
	clientId: string
	redirectUri: string
}) => {
	if (!clientId || !redirectUri) {
		return false
	}

	const result = await db
		.select()
		.from(applicationRedirectUris)
		.where(
			and(
				eq(applicationRedirectUris.appId, clientId),
				eq(applicationRedirectUris.uri, redirectUri)
			)
		)
		.get()

	if (!result) {
		return false
	}

	return true
}

export const getApplicationDetails = async ({ appId }: { appId: string }) => {
	const result = await db
		.select({
			appId: applications.appId,
			appName: applications.appName
		})
		.from(applications)
		.where(eq(applications.appId, appId))
		.get()

	if (!result) {
		throw new HTTPException(404, {
			message: `Aplicação com AppID: ${appId} não foi encontrada`
		})
	}

	return result
}

export const listApplications = async () => {
	return await db.select().from(applications).orderBy(applications.appName)
}

export const listApplicationsWithCounts = async () => {
	const rolesCountSubquery = db.$with("roles_count").as(
		db
			.select({
				appId: roles.appId,
				count: sql<number>`cast(count(${roles.roleId}) as int)`.as("roles_count")
			})
			.from(roles)
			.groupBy(roles.appId)
	)

	const usersCountSubquery = db.$with("users_count").as(
		db
			.select({
				appId: userApplicationAccess.appId,
				count: sql<number>`cast(count(distinct ${userApplicationAccess.userId}) as int)`.as(
					"users_count"
				)
			})
			.from(userApplicationAccess)
			.groupBy(userApplicationAccess.appId)
	)

	const results = await db
		.with(rolesCountSubquery, usersCountSubquery)
		.select({
			appId: applications.appId,
			appName: applications.appName,
			rolesCount: sql<number>`coalesce(${rolesCountSubquery.count}, 0)`.as("rolesCount"),
			usersCount: sql<number>`coalesce(${usersCountSubquery.count}, 0)`.as("usersCount")
		})
		.from(applications)
		.leftJoin(rolesCountSubquery, eq(applications.appId, rolesCountSubquery.appId))
		.leftJoin(usersCountSubquery, eq(applications.appId, usersCountSubquery.appId))
		.orderBy(applications.appName)

	return results
}

export const createApplication = async (data: {
	appId: string
	appName: string
}) => {
	const appExists = await db
		.select()
		.from(applications)
		.where(eq(applications.appId, data.appId))
		.get()

	if (appExists) {
		throw new HTTPException(409, {
			message: `Aplicação com AppID: ${data.appId} já existe`
		})
	}

	await db.insert(applications).values({
		appId: data.appId,
		appName: data.appName
	})
}
