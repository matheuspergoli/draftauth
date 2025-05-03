import crypto from "node:crypto"

export class ApiClientError extends Error {
	readonly status?: number
	readonly data?: unknown

	constructor(message: string, status?: number, data?: unknown) {
		super(message)
		this.name = "ApiClientError"
		this.status = status
		this.data = data

		if (Error.captureStackTrace) {
			Error.captureStackTrace(this, ApiClientError)
		}
	}
}

interface DraftauthServiceClientConfig {
	apiUrl: string
	apiKeyId: string
	apiSecretKey: string
}

const TIMESTAMP_HEADER = "x-request-timestamp"
const KEY_ID_HEADER = "x-api-key-id"
const SIGNATURE_HEADER = "x-signature"
const DIGEST_HEADER = "digest"

export class DraftauthServiceClient {
	private readonly config: DraftauthServiceClientConfig

	constructor(config: DraftauthServiceClientConfig) {
		if (!config.apiUrl || !config.apiKeyId || !config.apiSecretKey) {
			throw new Error(
				"DraftAuth Service Client: apiUrl, apiKeyId, e apiSecretKey são obrigatórios"
			)
		}

		this.config = { ...config, apiUrl: config.apiUrl.replace(/\/$/, "") }
	}

	private async _makeSignedRequest<TResponse>(
		method: "GET" | "POST" | "PUT" | "DELETE",
		path: string,
		body?: unknown
	): Promise<TResponse> {
		const url = new URL(path, this.config.apiUrl)
		const bodyString = body ? JSON.stringify(body) : ""
		const timestamp = Date.now().toString()

		let digestHeaderValue = ""
		if (bodyString) {
			const hash = crypto.createHash("sha256").update(bodyString)
			digestHeaderValue = `SHA-256=${hash.digest("base64")}`
		}

		const pathAndQuery = url.pathname + url.search
		const stringToSign = `${method.toUpperCase()}\n${pathAndQuery}\n${timestamp}\n${digestHeaderValue}`

		const signature = crypto
			.createHmac("sha256", this.config.apiSecretKey)
			.update(stringToSign)
			.digest("base64")

		const headers: HeadersInit = {
			Accept: "application/json",
			[KEY_ID_HEADER]: this.config.apiKeyId,
			[TIMESTAMP_HEADER]: timestamp,
			[SIGNATURE_HEADER]: signature
		}

		if (bodyString) {
			headers["Content-Type"] = "application/json"
			headers[DIGEST_HEADER] = digestHeaderValue
		}

		const response = await fetch(url.toString(), {
			method: method,
			headers: headers,
			body: bodyString ? bodyString : undefined
		})

		if (!response.ok) {
			let errorPayload: unknown = null
			let errorMessageFromServer: string | null = null
			try {
				const text = await response.text()
				if (text) {
					errorPayload = JSON.parse(text)
					if (
						errorPayload &&
						typeof errorPayload === "object" &&
						"message" in errorPayload &&
						typeof errorPayload.message === "string"
					) {
						errorMessageFromServer = errorPayload.message
					}
				}
			} catch (e) {
				/* ignora isso aqui por enquanto */
			}

			const errorMessage = errorMessageFromServer || response.statusText || "Erro desconhecido"
			throw new ApiClientError(
				`API Error ${response.status}: ${errorMessage}`,
				response.status,
				errorPayload
			)
		}

		if (response.status === 204) {
			return undefined as TResponse
		}

		try {
			const data = await response.json()
			return data as TResponse
		} catch (error) {
			throw new ApiClientError(
				"Falha ao processar resposta da API (JSON inválido).",
				response.status,
				await response.text().catch(() => "")
			)
		}
	}

	async getUserAccess(body: { userId: string }) {
		const path = `/api/service/users/${body.userId}/access`
		return await this._makeSignedRequest<"enabled" | "disabled">("GET", path)
	}

	async setUserAccess(body: {
		userId: string
		status: "enabled" | "disabled"
	}) {
		const path = `/api/service/users/${body.userId}/access`
		return await this._makeSignedRequest("PUT", path, body)
	}

	async assignRoleToUser(body: { roleName: string; userId: string }) {
		const path = `/api/service/roles/${body.userId}/assign`
		return await this._makeSignedRequest("POST", path, body)
	}

	async revokeRoleFromUser(body: { userId: string; roleName: string }) {
		const path = `/api/service/users/${body.userId}/revoke`
		return await this._makeSignedRequest("DELETE", path, body)
	}
}

export const createDraftauthServiceClient = (
	config: DraftauthServiceClientConfig
): DraftauthServiceClient => {
	return new DraftauthServiceClient(config)
}
