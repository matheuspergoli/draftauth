import { db } from "@/db/client"
import { applicationApiKeys } from "@/db/schema"
import {
	type EncryptedPayload,
	decryptSecret,
	encryptSecret,
	generateKeyId,
	generateSecretKey
} from "@/libs/crypto"
import { eq } from "drizzle-orm"
import { HTTPException } from "hono/http-exception"

export const generateApiKey = async ({
	appId
}: {
	appId: string
}) => {
	const secretKey = generateSecretKey()
	const keyId = generateKeyId(`sk_${appId}`)

	const now = Date.now()
	const encryptedPayload = encryptSecret(secretKey)
	const storedEncryptedSecret = JSON.stringify(encryptedPayload)

	await db.insert(applicationApiKeys).values({
		keyId,
		appId,
		createdAt: now,
		encryptedSecretKey: storedEncryptedSecret
	})

	const metadata = {
		keyId,
		appId,
		createdAt: now
	}

	const keyFileData = `API_KEY_ID=${keyId}\nAPI_SECRET_KEY=${secretKey}\n`

	return { metadata, keyFileData }
}

export const listApiKeysForApp = async ({ appId }: { appId: string }) => {
	const results = await db
		.select({
			keyId: applicationApiKeys.keyId,
			appId: applicationApiKeys.appId,
			createdAt: applicationApiKeys.createdAt
		})
		.from(applicationApiKeys)
		.where(eq(applicationApiKeys.appId, appId))
		.orderBy(applicationApiKeys.createdAt)

	return results
}

export const getApiKeyDetailsForKeyId = async ({ keyId }: { keyId: string }) => {
	const requestedApiKey = await db
		.select()
		.from(applicationApiKeys)
		.where(eq(applicationApiKeys.keyId, keyId))
		.get()

	if (!requestedApiKey) {
		throw new HTTPException(400, { message: `API Key com KeyID: ${keyId} não foi encontrada` })
	}

	return requestedApiKey
}

export const revokeApiKey = async ({ keyId }: { keyId: string }) => {
	await db.delete(applicationApiKeys).where(eq(applicationApiKeys.keyId, keyId))
}

export const getDecryptedSecretForKeyId = async ({ keyId }: { keyId: string }) => {
	const result = await db
		.select({
			encryptedSecretKey: applicationApiKeys.encryptedSecretKey
		})
		.from(applicationApiKeys)
		.where(eq(applicationApiKeys.keyId, keyId))
		.get()

	if (!result) {
		return null
	}

	try {
		const encryptedPayload = JSON.parse(result.encryptedSecretKey) as EncryptedPayload

		const decryptedSecret = decryptSecret(encryptedPayload)
		return decryptedSecret
	} catch (error) {
		return null
	}
}
