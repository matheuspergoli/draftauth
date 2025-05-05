import { randomUUID } from "node:crypto"
import { db } from "@/db/client"
import { type ProviderName, type UserStatus, userExternalIdentities, users } from "@/db/schema"
import { and, eq } from "drizzle-orm"
import { HTTPException } from "hono/http-exception"

export interface FindOrCreateUserResult {
	created: boolean
	user: { userId: string; email: string; status: UserStatus }
}

export const findUserByEmail = async ({
	email
}: {
	email: string
}) => {
	const result = await db
		.select({
			userId: users.userId,
			email: users.email,
			status: users.status
		})
		.from(users)
		.where(eq(users.email, email))
		.get()

	return result ?? null
}

export const findUserByExternalId = async ({
	providerName,
	providerUserId
}: {
	providerName: ProviderName
	providerUserId: string
}) => {
	const result = await db
		.select({
			userId: users.userId,
			email: users.email,
			status: users.status
		})
		.from(users)
		.innerJoin(userExternalIdentities, eq(users.userId, userExternalIdentities.userId))
		.where(
			and(
				eq(userExternalIdentities.providerName, providerName),
				eq(userExternalIdentities.providerUserId, providerUserId)
			)
		)
		.get()

	return result ?? null
}

export const createUser = async ({
	email,
	initialStatus = "active"
}: {
	email: string
	initialStatus?: UserStatus
}) => {
	const newUserId = randomUUID()

	const newUser = await db
		.insert(users)
		.values({
			email,
			userId: newUserId,
			status: initialStatus
		})
		.returning()
		.get()

	return newUser
}

export const linkExternalIdentity = async ({
	userId,
	providerName,
	providerUserId
}: {
	userId: string
	providerName: ProviderName
	providerUserId: string
}): Promise<void> => {
	await db
		.insert(userExternalIdentities)
		.values({
			userId,
			providerName,
			providerUserId
		})
		.onConflictDoNothing()
}

export const findOrCreateUser = async ({
	providerName,
	providerUserId,
	verifiedEmail
}: {
	providerName: ProviderName
	providerUserId: string
	verifiedEmail: string
}) => {
	let user = await findUserByExternalId({ providerName, providerUserId })
	if (user) {
		return { user, created: false }
	}

	user = await findUserByEmail({ email: verifiedEmail })

	if (user) {
		await linkExternalIdentity({ userId: user.userId, providerName, providerUserId })
		return { user, created: false }
	}

	user = await createUser({ email: verifiedEmail })
	await linkExternalIdentity({ userId: user.userId, providerName, providerUserId })

	return { user, created: true }
}

export const getUserDetails = async ({
	userId
}: {
	userId: string
}) => {
	const requestedUser = await db
		.select({
			userId: users.userId,
			email: users.email,
			status: users.status,
			createdAt: users.createdAt
		})
		.from(users)
		.where(eq(users.userId, userId))
		.get()

	if (!requestedUser) {
		throw new HTTPException(404, { message: `Usuário com ID: ${userId} não encontrado` })
	}

	return requestedUser
}

export const listUsers = async () => {
	return await db
		.select({
			userId: users.userId,
			email: users.email,
			status: users.status
		})
		.from(users)
		.orderBy(users.createdAt)
}

export const setUserGlobalStatus = async ({
	userId,
	status
}: { userId: string; status: UserStatus }) => {
	const requestedUser = await db.select().from(users).where(eq(users.userId, userId)).get()

	if (!requestedUser) {
		throw new HTTPException(404, { message: `Usuário com ID: ${userId} não foi encontrado` })
	}

	await db.update(users).set({ status: status }).where(eq(users.userId, userId))
}

export const getUserGlobalStatus = async ({
	userId
}: {
	userId: string
}) => {
	const requestedUser = await db.select().from(users).where(eq(users.userId, userId)).get()

	if (!requestedUser) {
		throw new HTTPException(404, { message: `Usuário com ID: ${userId} não foi encontrado` })
	}

	const result = await db
		.select({ status: users.status })
		.from(users)
		.where(eq(users.userId, userId))
		.get()

	if (!result) {
		throw new HTTPException(404, {
			message: `Não foi possível encontrar status para usuário com ID: ${userId}`
		})
	}

	return result.status
}
