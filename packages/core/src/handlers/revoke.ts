import type { Hono } from "hono"
/**
 * Token revocation endpoint handler for Draft Auth issuer.
 * Handles OAuth 2.0 token revocation with SSO session cleanup.
 */
import { cors } from "hono/cors"
import { Storage, type StorageAdapter } from "../storage/storage"

/**
 * Refresh token storage payload structure.
 * Contains metadata about issued refresh tokens.
 */
interface RefreshTokenStoragePayload {
	/** Subject type identifier */
	type: string
	/** Subject properties/claims */
	properties: unknown
	/** Resolved subject identifier for JWT */
	subject: string
	/** Client identifier that owns this refresh token */
	clientID: string
	/** OAuth 2.0 scopes associated with this token */
	scopes?: string[]
	/** Timestamp when the refresh token was first used */
	timeUsed?: number
}

/**
 * SSO session data structure for cleanup operations.
 * Contains session information needed for revocation.
 */
interface SsoSessionData {
	/** Unique identifier of the user */
	userId: string
	/** Type of the subject */
	subjectType: string
	/** User's email */
	email?: string
	/** User's full name */
	name?: string
	/** User's preferred username */
	preferred_username?: string
	/** User's profile picture URL */
	picture?: string
	/** Authentication time (seconds since epoch) */
	auth_time: number
	/** Session expiration time (seconds since epoch) */
	exp: number
	/** Session ID for OIDC Session Management */
	sid: string
	/** Resolved subject identifier for JWT tokens */
	resolvedSubject: string
	/** Original subject properties from authentication */
	originalProperties: Record<string, unknown>
}

/**
 * Token revocation request parameters.
 * Contains parameters sent in the revocation request.
 */
interface RevocationRequestParams {
	/** The token to be revoked */
	token?: string
	/** Hint about the type of token being revoked */
	token_type_hint?: string
	/** Whether to revoke all tokens for the subject */
	revoke_all?: boolean
	/** Client ID for scoped revocation */
	client_id?: string
}

/**
 * OAuth 2.0 error response structure.
 * Used for standardized error responses.
 */
interface OAuth2ErrorResponse {
	/** Error code following OAuth 2.0 specification */
	error: string
	/** Human-readable error description */
	error_description: string
}

/**
 * Revocation handler dependencies provided by the issuer.
 */
interface RevokeDependencies {
	/** Storage adapter for token and session management */
	storage: StorageAdapter
	/** SSO configuration */
	sso?: {
		enabled?: boolean
	}
}

/**
 * Parses refresh token format into subject and token ID components.
 * Refresh tokens are stored in format "subject:tokenId".
 *
 * @param token - The refresh token string to parse
 * @returns Object containing subject and tokenId, or null if invalid format
 */
const parseRefreshToken = (token: string): { subject: string; tokenId: string } | null => {
	const splits = token.split(":")
	const tokenId = splits.pop()
	const subject = splits.join(":")

	if (!subject || !tokenId) {
		return null
	}

	return { subject, tokenId }
}

/**
 * Extracts revocation parameters from form data.
 *
 * @param form - FormData from the revocation request
 * @returns Parsed revocation parameters
 */
const extractRevocationParams = (form: FormData): RevocationRequestParams => {
	return {
		token: form.get("token")?.toString(),
		token_type_hint: form.get("token_type_hint")?.toString(),
		revoke_all: form.get("revoke_all") === "true",
		client_id: form.get("client_id")?.toString()
	}
}

/**
 * Revokes all refresh tokens for a given subject.
 * Used when revoke_all parameter is true.
 *
 * @param storage - Storage adapter
 * @param subject - Subject identifier
 */
const revokeAllTokensForSubject = async (
	storage: StorageAdapter,
	subject: string
): Promise<void> => {
	const keys = await Array.fromAsync(Storage.scan(storage, ["oauth:refresh", subject]))
	await Promise.all(keys.map(([scanKey]) => Storage.remove(storage, scanKey)))
}

/**
 * Revokes all refresh tokens for a specific client within a subject.
 * Used when client_id parameter is provided without revoke_all.
 *
 * @param storage - Storage adapter
 * @param subject - Subject identifier
 * @param clientID - Client identifier
 */
const revokeTokensForClient = async (
	storage: StorageAdapter,
	subject: string,
	clientID: string
): Promise<void> => {
	const keys = await Array.fromAsync(Storage.scan(storage, ["oauth:refresh", subject]))

	for (const [scanKey] of keys) {
		const scanPayload = await Storage.get<RefreshTokenStoragePayload>(storage, scanKey)
		if (scanPayload && scanPayload.clientID === clientID) {
			await Storage.remove(storage, scanKey)
		}
	}
}

/**
 * Cleans up SSO sessions for a revoked subject.
 * Removes all SSO sessions associated with the subject.
 *
 * @param storage - Storage adapter
 * @param subject - Subject identifier to clean up
 */
const cleanupSsoSessions = async (storage: StorageAdapter, subject: string): Promise<void> => {
	const sessionKeys = await Array.fromAsync(Storage.scan(storage, ["sso:session"]))

	for (const [sessionKey] of sessionKeys) {
		const sessionData = await Storage.get<SsoSessionData>(storage, sessionKey)
		if (sessionData && sessionData.resolvedSubject === subject) {
			await Storage.remove(storage, sessionKey)
		}
	}
}

/**
 * Registers the OAuth 2.0 token revocation endpoint with the Hono application.
 *
 * @param app - Hono application instance
 * @param dependencies - Revocation handler dependencies
 */
export const registerRevokeEndpoint = <T>(
	app: Hono<{ Variables: { authorization: T } }>,
	dependencies: RevokeDependencies
): void => {
	const { storage, sso } = dependencies
	const ssoEnabled = sso?.enabled || false

	/**
	 * Token revocation endpoint.
	 * Revokes refresh tokens with support for bulk revocation and SSO cleanup.
	 *
	 * Standard endpoint: /revoke
	 */
	app.post(
		"/revoke",
		cors({
			origin: "*",
			allowHeaders: ["*"],
			allowMethods: ["POST"],
			credentials: false
		}),
		async (c) => {
			const form = await c.req.formData()
			const params = extractRevocationParams(form)

			// If no token provided, return success (200 OK)
			if (!params.token) {
				return c.newResponse(null, 200)
			}

			// Validate token type hint (only refresh tokens supported)
			if (params.token_type_hint && params.token_type_hint !== "refresh_token") {
				const errorResponse: OAuth2ErrorResponse = {
					error: "unsupported_token_type",
					error_description: "Revocation of access tokens is not supported"
				}
				return c.json(errorResponse, 400)
			}

			try {
				// Parse refresh token format (subject:tokenId)
				const parsedToken = parseRefreshToken(params.token)
				if (!parsedToken) {
					// Invalid token format should return success
					return c.newResponse(null, 200)
				}

				const { subject, tokenId } = parsedToken
				const tokenKey = ["oauth:refresh", subject, tokenId]
				const tokenPayload = await Storage.get<RefreshTokenStoragePayload>(storage, tokenKey)

				if (tokenPayload) {
					// Validate client ownership if client_id provided
					if (params.client_id && tokenPayload.clientID !== params.client_id) {
						const errorResponse: OAuth2ErrorResponse = {
							error: "invalid_client",
							error_description: "Token does not belong to the specified client"
						}
						return c.json(errorResponse, 400)
					}

					// Remove the specific token
					await Storage.remove(storage, tokenKey)

					// Handle bulk revocation scenarios
					if (params.revoke_all) {
						// Revoke all tokens for the subject
						await revokeAllTokensForSubject(storage, subject)

						// Clean up SSO sessions if enabled
						if (ssoEnabled) {
							await cleanupSsoSessions(storage, subject)
						}
					} else if (params.client_id) {
						// Revoke only tokens for specific client
						await revokeTokensForClient(storage, subject, params.client_id)
					}
				}

				return c.newResponse(null, 200)
			} catch (error) {
				console.error("Error revoking token:", error)
				return c.newResponse(null, 200)
			}
		}
	)
}
