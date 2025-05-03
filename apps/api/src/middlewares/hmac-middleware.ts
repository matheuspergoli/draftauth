import crypto from "node:crypto"
import { getDecryptedSecretForKeyId } from "@/services/api-key-service"
import { createMiddleware } from "hono/factory"
import { HTTPException } from "hono/http-exception"

const DIGEST_HEADER = "digest"
const KEY_ID_HEADER = "x-api-key-id"
const SIGNATURE_HEADER = "x-signature"
const TIMESTAMP_HEADER = "x-request-timestamp"
const ALLOWED_TIME_DRIFT_MS = 5 * 60 * 1000

const safeCompare = (a: string, b: string): boolean => {
	try {
		const bufA = Buffer.from(a)
		const bufB = Buffer.from(b)
		if (bufA.length !== bufB.length) {
			return false
		}
		return crypto.timingSafeEqual(bufA, bufB)
	} catch (error) {
		return false
	}
}

export interface HMACEnv {
	Variables: {
		serviceKeyId: string
	}
}

export const hmacAuthMiddleware = createMiddleware<HMACEnv>(async (c, next) => {
	const keyId = c.req.header(KEY_ID_HEADER)
	const receivedSignature = c.req.header(SIGNATURE_HEADER)
	const timestampHeader = c.req.header(TIMESTAMP_HEADER)
	const digestHeader = c.req.header(DIGEST_HEADER)

	if (!keyId || !receivedSignature || !timestampHeader) {
		throw new HTTPException(401, {
			message: `Faltando headers obrigatórios: ${KEY_ID_HEADER}, ${SIGNATURE_HEADER}, ${TIMESTAMP_HEADER}`
		})
	}

	const requestTimestamp = Number.parseInt(timestampHeader, 10)
	if (Number.isNaN(requestTimestamp)) {
		throw new HTTPException(400, {
			message: `Formato do header ${TIMESTAMP_HEADER} inválido.`
		})
	}

	const now = Date.now()
	if (Math.abs(now - requestTimestamp) > ALLOWED_TIME_DRIFT_MS) {
		throw new HTTPException(401, { message: "Timestamp da request está inválido ou expirado" })
	}

	const secretKey = await getDecryptedSecretForKeyId({ keyId: keyId })
	if (!secretKey) {
		throw new HTTPException(403, { message: "API Key ID não autorizado" })
	}

	let bodyDigest = ""
	const method = c.req.method.toUpperCase()
	if (method === "POST" || method === "PUT" || method === "PATCH") {
		if (!digestHeader || !digestHeader.toLowerCase().startsWith("sha-256=")) {
			throw new HTTPException(400, {
				message: `Header ${DIGEST_HEADER} está faltando ou inválido para ${method} request.`
			})
		}
		const receivedDigestBase64 = digestHeader.substring(8)

		try {
			const requestBody = await c.req.text()
			const hash = crypto.createHash("sha256")
			hash.update(requestBody)
			const calculatedDigestBase64 = hash.digest("base64")

			bodyDigest = `SHA-256=${calculatedDigestBase64}`

			if (!safeCompare(calculatedDigestBase64, receivedDigestBase64)) {
				throw new HTTPException(403, {
					message: "Integridade da checagem do request body falhou"
				})
			}
		} catch (err) {
			throw new HTTPException(400, {
				message: "Não foi possível validar o request body digest"
			})
		}
	} else {
		bodyDigest = digestHeader || ""
	}

	const url = new URL(c.req.url)
	const pathAndQuery = url.pathname + url.search

	const stringToSign = `${method}\n${pathAndQuery}\n${timestampHeader}\n${bodyDigest}`

	const calculatedSignature = crypto
		.createHmac("sha256", secretKey)
		.update(stringToSign)
		.digest("base64")

	if (!safeCompare(receivedSignature, calculatedSignature)) {
		throw new HTTPException(401, { message: "Assinatura inválida" })
	}

	c.set("serviceKeyId", keyId)

	await next()
})
