/**
 * Token introspection endpoint handler for Draft Auth issuer.
 */
import type { Context, Hono } from "hono"
import { cors } from "hono/cors"
import { jwtVerify } from "jose"
import { OauthError } from "../error"
import type { KeyPair } from "../keys"

/**
 * Contains information about the token's validity and associated claims.
 */
interface IntrospectionResponse {
	/** Whether the token is currently active */
	active: boolean
	/** OAuth 2.0 scopes associated with the token */
	scope?: string
	/** Client identifier for the OAuth 2.0 client that requested this token */
	client_id?: string
	/** Machine-readable identifier of the resource owner who authorized this token */
	username?: string
	/** Type of the token (Bearer) */
	token_type?: string
	/** Token expiration timestamp (seconds since epoch) */
	exp?: number
	/** Token issued at timestamp (seconds since epoch) */
	iat?: number
	/** Subject of the token (usually user identifier) */
	sub?: string
	/** Intended audience of the token */
	aud?: string
	/** Issuer of the token */
	iss?: string
}

/**
 * Client authentication methods supported for introspection endpoint.
 */
interface ClientAuthentication {
	/** Authentication method used */
	method: "none" | "client_secret_post" | "client_secret_basic"
	/** Client identifier */
	clientId: string
	/** Client secret (for authenticated clients) */
	clientSecret?: string
}

/**
 * Introspection handler dependencies provided by the issuer.
 */
interface IntrospectionDependencies {
	/** Function to get all signing keys for token verification */
	allSigning: () => Promise<KeyPair[]>
	/** Function to resolve issuer URL from context */
	issuer: (ctx: Context) => string
}

/**
 * Extracts client authentication from request.
 * Supports client_secret_basic (Authorization header) and client_secret_post (form data).
 */
const extractClientAuthentication = async (c: Context): Promise<ClientAuthentication> => {
	// Check Authorization header for Basic authentication
	const authHeader = c.req.header("authorization")
	if (authHeader?.startsWith("Basic ")) {
		const credentials = atob(authHeader.slice(6))
		const [clientId, clientSecret] = credentials.split(":")

		if (!clientId) {
			throw new OauthError(
				"invalid_client",
				"Invalid client credentials in Authorization header"
			)
		}

		return {
			method: "client_secret_basic",
			clientId,
			clientSecret
		}
	}

	// Check form data for client credentials
	const formData = await c.req.formData()
	const clientId = formData.get("client_id")?.toString()
	const clientSecret = formData.get("client_secret")?.toString()

	if (!clientId) {
		throw new OauthError("invalid_request", "Missing client_id parameter")
	}

	return {
		method: clientSecret ? "client_secret_post" : "none",
		clientId,
		clientSecret
	}
}

/**
 * Validates and extracts claims from a JWT access token.
 * Returns null if token is invalid or expired.
 */
const validateAccessToken = async (
	token: string,
	signingKeys: KeyPair[],
	expectedIssuer: string
): Promise<Record<string, unknown> | null> => {
	try {
		// Try each signing key until one works
		for (const keyInfo of signingKeys) {
			try {
				const { payload } = await jwtVerify(token, keyInfo.public, {
					issuer: expectedIssuer,
					algorithms: [keyInfo.alg]
				})

				// Verify it's an access token
				if (payload.mode !== "access") {
					continue
				}

				// Check expiration with small buffer
				const now = Math.floor(Date.now() / 1000)
				if (payload.exp && payload.exp <= now) {
					return null // Token expired
				}

				return payload
			} catch (error) {
				// Try next key
				continue
			}
		}

		return null // No valid signature found
	} catch (error) {
		return null // Invalid token format
	}
}

/**
 * Registers OAuth 2.0 token introspection endpoint with the Hono application.
 *
 * Security considerations:
 * - Requires client authentication to prevent token scanning attacks
 * - Supports TLS (enforced by deployment environment)
 * - Uses POST method to prevent tokens from appearing in server logs
 * - Returns minimal information for inactive tokens
 *
 * @param app - Hono application instance
 * @param dependencies - Introspection handler dependencies
 */
export const registerIntrospectionEndpoint = <T>(
	app: Hono<{ Variables: { authorization: T } }>,
	dependencies: IntrospectionDependencies
): void => {
	const { allSigning, issuer } = dependencies

	/**
	 * Token introspection endpoint.
	 * Validates OAuth 2.0 access tokens and returns metadata.
	 *
	 * Standard endpoint: /introspect
	 * Method: POST
	 * Authentication: Client credentials required
	 */
	app.post(
		"/introspect",
		cors({
			origin: "*",
			allowHeaders: ["Content-Type", "Authorization"],
			allowMethods: ["POST"],
			credentials: false
		}),
		async (c) => {
			try {
				// Extract client authentication
				const clientAuth = await extractClientAuthentication(c)

				// Basic client authentication - just verify client_id is provided
				if (!clientAuth.clientId) {
					throw new OauthError("invalid_client", "Client authentication required")
				}

				// Extract token from form data
				const formData = await c.req.formData()
				const token = formData.get("token")?.toString()

				if (!token) {
					throw new OauthError("invalid_request", "Missing token parameter")
				}

				// Get signing keys and issuer URL
				const signingKeys = await allSigning()
				const issuerUrl = issuer(c)

				// Validate the access token
				const tokenData = await validateAccessToken(token, signingKeys, issuerUrl)

				if (!tokenData) {
					// Token is invalid or expired - return minimal response
					const inactiveResponse: IntrospectionResponse = {
						active: false
					}
					return c.json(inactiveResponse)
				}

				// Token is valid - return full metadata
				const activeResponse: IntrospectionResponse = {
					active: true,
					scope: Array.isArray(tokenData.scopes) ? tokenData.scopes.join(" ") : undefined,
					client_id: tokenData.aud as string,
					username: tokenData.sub as string,
					token_type: "Bearer",
					exp: tokenData.exp as number,
					iat: tokenData.iat as number,
					sub: tokenData.sub as string,
					aud: tokenData.aud as string,
					iss: tokenData.iss as string
				}

				return c.json(activeResponse)
			} catch (error) {
				// Handle OAuth errors
				if (error instanceof OauthError) {
					return c.json(
						{
							error: error.error,
							error_description: error.description
						},
						error.error === "invalid_client" ? 401 : 400
					)
				}

				// Handle unexpected errors
				console.error("Token introspection error:", error)
				return c.json(
					{
						error: "server_error",
						error_description: "Internal server error during token introspection"
					},
					500
				)
			}
		}
	)
}
