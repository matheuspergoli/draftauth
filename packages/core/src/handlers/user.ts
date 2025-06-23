import type { Context, Hono } from "hono"
import { getCookie } from "hono/cookie"
/**
 * User endpoints handler for Draft Auth issuer.
 * Handles UserInfo and logout endpoints with SSO session management.
 */
import { cors } from "hono/cors"
import { jwtVerify } from "jose"
import {
	type ClaimsConfiguration,
	createDefaultClaimsConfig,
	transformClaims
} from "../claims"
import type { KeyPair } from "../keys"
import type { SsoSessionData } from "../sso"
import { Storage, type StorageAdapter } from "../storage/storage"

/**
 * UserInfo response structure following OIDC UserInfo specification.
 * Contains user claims based on requested scopes.
 */
interface UserInfoResponse {
	/** Subject identifier (always present) */
	sub: string
	/** User's full name (profile scope) */
	name?: string
	/** User's preferred username (profile scope) */
	preferred_username?: string
	/** User's profile picture URL (profile scope) */
	picture?: string
	/** User's email address (email scope) */
	email?: string
	/** Whether email has been verified (email scope) */
	email_verified?: boolean
}

/**
 * JWT payload structure for access token verification.
 * Contains token mode, type, properties, and scopes.
 */
interface AccessTokenPayload {
	/** Token mode (must be "access" for UserInfo) */
	mode: "access"
	/** Subject type identifier */
	type: string
	/** Subject properties/claims */
	properties: Record<string, unknown>
	/** OAuth 2.0 scopes associated with token */
	scopes?: string[]
	/** Subject identifier */
	sub: string
}


/**
 * User handler dependencies provided by the issuer.
 */
interface UserDependencies {
	/** Storage adapter for session management */
	storage: StorageAdapter
	/** Function to get signing key for JWT verification */
	signingKey: () => Promise<KeyPair | undefined>
	/** Function to resolve issuer URL from context */
	issuer: (ctx: Context) => string
	/** Authentication utilities */
	auth: {
		invalidate: (subject: string) => Promise<void>
	}
	/** SSO configuration */
	sso?: {
		enabled?: boolean
		postLogoutRedirectUri?: string
		postLogoutRedirectUris?: string[]
	}
	/** SSO utilities */
	ssoUtils: {
		getSsoCookieName: (c: Context) => string
		deleteSsoCookie: (c: Context) => void
	}
	/** Claims configuration for UserInfo transformation */
	claims?: ClaimsConfiguration
}

/**
 * Validates logout redirect URI against allowed URIs.
 *
 * @param uri - URI to validate
 * @param allowedUris - Array of allowed redirect URIs
 * @returns True if URI is allowed
 */
const validateLogoutRedirectUri = (uri: string, allowedUris?: string[]): boolean => {
	if (!allowedUris || allowedUris.length === 0) return false

	return allowedUris.some((allowedUri) => {
		try {
			const allowed = new URL(allowedUri)
			const requested = new URL(uri)
			return allowed.href === requested.href
		} catch {
			return false
		}
	})
}

/**
 * Registers user-related endpoints with the Hono application.
 * Handles UserInfo and logout endpoints with full OIDC compliance.
 *
 * @param app - Hono application instance
 * @param dependencies - User handler dependencies
 */
export const registerUserEndpoints = <T>(
	app: Hono<{ Variables: { authorization: T } }>,
	dependencies: UserDependencies
): void => {
	const { storage, signingKey, issuer, auth, sso, ssoUtils, claims } = dependencies
	const { getSsoCookieName, deleteSsoCookie } = ssoUtils

	/**
	 * UserInfo endpoint following OIDC UserInfo specification.
	 * Returns user claims based on access token scopes.
	 *
	 * Standard endpoint: /userinfo
	 * Specification: OpenID Connect Core 1.0 Section 5.3
	 */
	app.get(
		"/userinfo",
		cors({
			origin: "*",
			allowHeaders: ["*"],
			allowMethods: ["GET"],
			credentials: false
		}),
		async (c) => {
			const header = c.req.header("Authorization")

			if (!header) {
				return c.json(
					{
						error: "invalid_request",
						error_description: "Missing Authorization header"
					},
					400
				)
			}

			const [type, token] = header.split(" ")

			if (type !== "Bearer") {
				return c.json(
					{
						error: "invalid_request",
						error_description: "Missing or invalid Authorization header"
					},
					400
				)
			}

			if (!token) {
				return c.json(
					{
						error: "invalid_request",
						error_description: "Missing token"
					},
					400
				)
			}

			try {
				const signingKeyData = await signingKey()
				if (!signingKeyData) {
					return c.json(
						{
							error: "invalid_token",
							error_description: "Signing key not available"
						},
						401
					)
				}

				const result = await jwtVerify<AccessTokenPayload>(token, signingKeyData.public, {
					issuer: issuer(c)
				})

				if (result.payload.mode !== "access") {
					return c.json(
						{
							error: "invalid_token",
							error_description: "Invalid token type"
						},
						401
					)
				}

				if (!result.payload.scopes?.includes("openid")) {
					return c.json(
						{
							error: "insufficient_scope",
							error_description: "Token does not have openid scope"
						},
						403
					)
				}

				// Standard UserInfo claims (always included)
				const standardClaims: UserInfoResponse = {
					sub: result.payload.sub
				}

				const props = result.payload.properties
				const scopes = result.payload.scopes || []

				// Transform claims using configuration or default behavior
				const claimsConfig = claims || createDefaultClaimsConfig()
				const transformContext = {
					clientID: result.payload.aud as string,
					scopes,
					target: "userinfo" as const,
					issuer: issuer(c)
				}

				const transformedClaims = await transformClaims(props, transformContext, claimsConfig)

				if (transformedClaims === null) {
					return c.json(
						{
							error: "server_error",
							error_description: "Essential claims validation failed"
						},
						500
					)
				}

				// Merge standard claims with transformed claims
				// Standard claims take precedence to ensure OIDC compliance
				const finalUserInfo = {
					...transformedClaims,
					...standardClaims
				}

				return c.json(finalUserInfo)
			} catch {
				return c.json(
					{
						error: "invalid_token",
						error_description: "Token verification failed"
					},
					401
				)
			}
		}
	)

	/**
	 * Logout endpoint following OIDC RP-Initiated Logout specification.
	 * Terminates SSO sessions and redirects to appropriate logout URIs.
	 *
	 * Standard endpoint: /logout
	 * Specification: OpenID Connect RP-Initiated Logout 1.0
	 */
	app.get("/logout", async (c) => {
		const idTokenHint = c.req.query("id_token_hint")
		const postLogoutRedirectUri = c.req.query("post_logout_redirect_uri")
		const state = c.req.query("state")

		let sessionSub: string | undefined

		// Validate ID token hint if provided
		if (idTokenHint) {
			try {
				const signingKeyData = await signingKey()
				if (signingKeyData) {
					const result = await jwtVerify(idTokenHint, signingKeyData.public, {
						issuer: issuer(c)
					})
					sessionSub = result.payload.sub as string
				}
			} catch {
				// Invalid ID token hint - continue silently
			}
		}

		// Handle SSO session cleanup
		const ssoCookieName = getSsoCookieName(c)
		const ssoSessionId = getCookie(c, ssoCookieName)

		if (ssoSessionId) {
			const ssoSessionKey = ["sso:session", ssoSessionId]
			const ssoSessionData = await Storage.get<SsoSessionData>(storage, ssoSessionKey)

			if (ssoSessionData) {
				// Only invalidate if no session subject specified or if it matches
				if (!sessionSub || ssoSessionData.resolvedSubject === sessionSub) {
					await auth.invalidate(ssoSessionData.resolvedSubject)
					await Storage.remove(storage, ssoSessionKey)
				}
			}
			deleteSsoCookie(c)
		}

		// Handle post-logout redirect URI from request parameter
		let redirectTo = postLogoutRedirectUri
		if (redirectTo && validateLogoutRedirectUri(redirectTo, sso?.postLogoutRedirectUris)) {
			const redirectUrl = new URL(redirectTo)
			if (state) {
				redirectUrl.searchParams.set("state", state)
			}
			return c.redirect(redirectUrl.toString(), 302)
		}

		// Handle default post-logout redirect URI from configuration
		redirectTo = sso?.postLogoutRedirectUri
		if (redirectTo) {
			const redirectUrl = new URL(redirectTo)
			if (state) {
				redirectUrl.searchParams.set("state", state)
			}
			return c.redirect(redirectUrl.toString(), 302)
		}

		// Default logout success page
		return c.html(`
			<!DOCTYPE html>
			<html>
			<head>
				<title>Logout Successful</title>
				<meta charset="utf-8">
				<meta name="viewport" content="width=device-width, initial-scale=1">
				<style>
					body {
						font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
						margin: 0;
						padding: 40px 20px;
						background-color: #f8f9fa;
						text-align: center;
					}
					.container {
						max-width: 400px;
						margin: 0 auto;
						background: white;
						padding: 40px;
						border-radius: 8px;
						box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
					}
					h1 {
						color: #28a745;
						margin-bottom: 16px;
					}
					p {
						color: #6c757d;
						line-height: 1.5;
					}
				</style>
			</head>
			<body>
				<div class="container">
					<h1>Logout Successful</h1>
					<p>You have been successfully logged out from Draft Auth.</p>
					${state ? `<p>State: ${state}</p>` : ""}
				</div>
			</body>
			</html>
		`)
	})
}
