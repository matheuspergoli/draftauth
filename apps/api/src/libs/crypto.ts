import crypto from "node:crypto"
import { env } from "@/environment/env"

const ALGORITHM = "aes-256-gcm"
const IV_LENGTH = 12
const SALT_LENGTH = 16
const PBKDF2_ITERATIONS = 200000
const PBKDF2_DIGEST = "sha512"
const KEY_LENGTH = 32

const MASTER_PASSWORD = env.API_SECRET_ENCRYPTION_KEY

export interface EncryptedPayload {
	salt: string
	iv: string
	authTag: string
	encryptedData: string
}

export const encryptSecret = (plaintext: string): EncryptedPayload => {
	try {
		const salt = crypto.randomBytes(SALT_LENGTH)

		const derivedKey = crypto.pbkdf2Sync(
			MASTER_PASSWORD,
			salt,
			PBKDF2_ITERATIONS,
			KEY_LENGTH,
			PBKDF2_DIGEST
		)

		const iv = crypto.randomBytes(IV_LENGTH)

		const cipher = crypto.createCipheriv(ALGORITHM, derivedKey, iv)
		let encrypted = cipher.update(plaintext, "utf8", "base64")
		encrypted += cipher.final("base64")
		const authTag = cipher.getAuthTag()

		return {
			salt: salt.toString("base64"),
			iv: iv.toString("base64"),
			encryptedData: encrypted,
			authTag: authTag.toString("base64")
		}
	} catch (error) {
		throw new Error("Falha na criptografia do segredo.")
	}
}

export const decryptSecret = (payload: EncryptedPayload): string => {
	try {
		const salt = Buffer.from(payload.salt, "base64")
		const iv = Buffer.from(payload.iv, "base64")
		const authTag = Buffer.from(payload.authTag, "base64")
		const encryptedData = payload.encryptedData

		const derivedKey = crypto.pbkdf2Sync(
			MASTER_PASSWORD,
			salt,
			PBKDF2_ITERATIONS,
			KEY_LENGTH,
			PBKDF2_DIGEST
		)

		const decipher = crypto.createDecipheriv(ALGORITHM, derivedKey, iv)
		decipher.setAuthTag(authTag)

		let decrypted = decipher.update(encryptedData, "base64", "utf8")
		decrypted += decipher.final("utf8")

		return decrypted
	} catch (error) {
		throw new Error("Falha na descriptografia ou segredo inválido/corrompido.")
	}
}

export const generateSecretKey = (length = 32): string => {
	return crypto.randomBytes(length).toString("base64url")
}

export const generateKeyId = (prefix = "sk_live"): string => {
	return `${prefix}_${crypto
		.randomBytes(18)
		.toString("base64url")
		.replace(/[^a-zA-Z0-9]/g, "")}`
}
