/**
 * Single Sign-On (SSO) module for Draft Auth.
 * Provides enterprise-grade SSO session management with OIDC compliance.
 *
 * ## Quick Setup
 *
 * ```ts
 * export default issuer({
 *   sso: {
 *     enabled: true,
 *     cookieDomain: ".mycompany.com"
 *   }
 * })
 * ```
 *
 * @packageDocumentation
 */

import type { Context } from "hono"
import { deleteCookie, getCookie, setCookie } from "hono/cookie"
import { MissingParameterError, UnauthorizedClientError } from "./error"
import { Storage, type StorageAdapter } from "./storage/storage"
import type { AuthorizationState } from "./types"

/**
 * Simplified SSO session data following OIDC Session Management specification.
 * Contains only essential information for cross-application authentication.
 */
export interface SsoSessionData {
	/** Unique identifier of the user for session validation */
	userId: string
	/** Subject type (user, admin, etc.) from the authentication callback */
	subjectType: string
	/** Authentication time (OIDC 'auth_time') */
	auth_time: number
	/** Session expiration time (OIDC 'exp') */
	exp: number
	/** Session ID for OIDC Session Management (OIDC 'sid') */
	sid: string
	/** Resolved subject identifier for JWT tokens */
	resolvedSubject: string
	/** Complete user data from authentication provider */
	originalProperties: Record<string, unknown>
}

/**
 * Simplified SSO configuration options.
 * Contains only actively used configuration properties.
 */
export interface SsoConfiguration {
	/**
	 * Whether SSO is enabled for this issuer instance.
	 *
	 * @default false
	 */
	enabled?: boolean

	/**
	 * Domain for the SSO cookie to enable cross-subdomain SSO.
	 *
	 * @example ".mycompany.com"
	 */
	cookieDomain?: string
}

const DEFAULT_SSO_COOKIE_NAME_SECURE = "__Host-draftauth-sso"
const DEFAULT_SSO_COOKIE_NAME_INSECURE = "draftauth-sso"
const DEFAULT_SSO_SESSION_TTL_SECONDS = 60 * 60 * 24 * 7

/**
 * SSO lock management for concurrent session operations.
 */
const ssoLocks: Record<string, Promise<unknown>> = {}

/**
 * Gets SSO cookie name based on HTTPS detection.
 */
const getSsoCookieName = (
	ctx: Context,
	config: SsoConfiguration,
	isHttpsRequest: (ctx: Context) => boolean
): string => {
	const isHttps = isHttpsRequest(ctx)
	if (config.cookieDomain) {
		return isHttps ? "draftauth-sso-secure" : "draftauth-sso"
	}
	return isHttps ? DEFAULT_SSO_COOKIE_NAME_SECURE : DEFAULT_SSO_COOKIE_NAME_INSECURE
}

/**
 * Sets SSO session cookie with appropriate security settings.
 */
const setSsoCookie = (
	ctx: Context,
	sessionId: string,
	config: SsoConfiguration,
	isHttpsRequest: (ctx: Context) => boolean
): void => {
	const isHttps = isHttpsRequest(ctx)
	const cookieName = getSsoCookieName(ctx, config, isHttpsRequest)

	setCookie(ctx, cookieName, sessionId, {
		path: "/",
		httpOnly: true,
		secure: isHttps,
		sameSite: "Lax" as const,
		maxAge: DEFAULT_SSO_SESSION_TTL_SECONDS,
		...(config.cookieDomain && { domain: config.cookieDomain })
	})
}

/**
 * Deletes SSO session cookie.
 */
const deleteSsoCookie = (
	ctx: Context,
	config: SsoConfiguration,
	isHttpsRequest: (ctx: Context) => boolean
): void => {
	const cookieName = getSsoCookieName(ctx, config, isHttpsRequest)
	const isHttps = isHttpsRequest(ctx)

	deleteCookie(ctx, cookieName, {
		path: "/",
		httpOnly: true,
		secure: isHttps,
		sameSite: "Lax" as const,
		...(config.cookieDomain && { domain: config.cookieDomain })
	})
}

/**
 * Acquires exclusive lock for SSO session operations to prevent race conditions.
 */
const acquireSsoLock = async <T>(
	sessionId: string,
	operation: () => Promise<T>
): Promise<T> => {
	if (ssoLocks[sessionId]) {
		await ssoLocks[sessionId]
	}

	const promise = operation()
	ssoLocks[sessionId] = promise

	try {
		return await promise
	} finally {
		delete ssoLocks[sessionId]
	}
}

/**
 * Creates a new SSO session for the authenticated user.
 */
const createSsoSession = async (
	ctx: Context,
	subjectType: string,
	properties: Record<string, unknown>,
	resolvedSubject: string,
	config: SsoConfiguration,
	storage: StorageAdapter,
	isHttpsRequest: (ctx: Context) => boolean
): Promise<string> => {
	if (!config.enabled) return ""

	// Extract minimal user identifier
	const userId = (properties.id ?? properties.userId ?? properties.sub) as string
	if (!userId) return ""

	const ssoSessionId = crypto.randomUUID()
	const authTime = Math.floor(Date.now() / 1000)
	const ssoExpiresAt = authTime + DEFAULT_SSO_SESSION_TTL_SECONDS

	const ssoSessionPayload: SsoSessionData = {
		userId,
		subjectType,
		auth_time: authTime,
		exp: ssoExpiresAt,
		sid: ssoSessionId,
		resolvedSubject,
		originalProperties: properties
	}

	await Storage.set(
		storage,
		["sso:session", ssoSessionId],
		ssoSessionPayload,
		DEFAULT_SSO_SESSION_TTL_SECONDS
	)

	setSsoCookie(ctx, ssoSessionId, config, isHttpsRequest)
	return ssoSessionId
}

/**
 * Validates an existing SSO session and checks user status.
 */
const validateSsoSession = async (
	sessionId: string,
	storage: StorageAdapter
): Promise<SsoSessionData | null> => {
	const ssoSessionKey = ["sso:session", sessionId]
	const ssoSessionData = await Storage.get<SsoSessionData>(storage, ssoSessionKey)

	if (!ssoSessionData) return null

	// Basic validation: structure and expiration
	const now = Math.floor(Date.now() / 1000)
	const isSsoSessionValid = ssoSessionData.userId && ssoSessionData.exp > now

	return isSsoSessionValid ? ssoSessionData : null
}

/**
 * Destroys an SSO session and cleans up associated data.
 */
const destroySsoSession = async (
	ctx: Context,
	sessionId: string,
	config: SsoConfiguration,
	storage: StorageAdapter,
	isHttpsRequest: (ctx: Context) => boolean
): Promise<void> => {
	await Storage.remove(storage, ["sso:session", sessionId])
	deleteSsoCookie(ctx, config, isHttpsRequest)
}

// ================================
// PUBLIC UTILITIES
// ================================

/**
 * SSO utilities for external use by handlers.
 */
export interface SsoUtils {
	getSsoCookieName: (ctx: Context) => string
	setSsoCookie: (ctx: Context, sessionId: string) => void
	deleteSsoCookie: (ctx: Context) => void
	acquireSsoLock: <T>(sessionId: string, operation: () => Promise<T>) => Promise<T>
}

/**
 * Creates SSO utilities for use by handlers.
 */
export const createSsoUtils = (
	config: SsoConfiguration,
	isHttpsRequest: (ctx: Context) => boolean
): SsoUtils => ({
	getSsoCookieName: (ctx: Context) => getSsoCookieName(ctx, config, isHttpsRequest),
	setSsoCookie: (ctx: Context, sessionId: string) =>
		setSsoCookie(ctx, sessionId, config, isHttpsRequest),
	deleteSsoCookie: (ctx: Context) => deleteSsoCookie(ctx, config, isHttpsRequest),
	acquireSsoLock: <T>(sessionId: string, operation: () => Promise<T>) =>
		acquireSsoLock(sessionId, operation)
})

/**
 * Creates SSO session during authentication.
 * Used by core.ts in the auth.success flow.
 */
export const handleSsoSessionCreation = createSsoSession

/**
 * Handles SSO authorization flow logic.
 * Used by authorize handler for existing SSO sessions.
 */
export const handleSsoAuthorizationFlow = async (
	ctx: Context,
	authorization: AuthorizationState,
	config: SsoConfiguration,
	storage: StorageAdapter,
	isHttpsRequest: (ctx: Context) => boolean,
	allowFn: (
		input: { clientID: string; redirectURI: string; audience?: string },
		req: Request
	) => Promise<boolean>
): Promise<Response | null> => {
	if (!config.enabled) return null

	const ssoCookieName = getSsoCookieName(ctx, config, isHttpsRequest)
	const ssoSessionIdFromCookie = getCookie(ctx, ssoCookieName)

	if (!ssoSessionIdFromCookie) return null

	return await acquireSsoLock(ssoSessionIdFromCookie, async () => {
		const ssoSessionData = await validateSsoSession(ssoSessionIdFromCookie, storage)

		if (!ssoSessionData) {
			deleteSsoCookie(ctx, config, isHttpsRequest)
			return null
		}

		// Handle OIDC prompt parameters
		if (authorization.prompt === "login") {
			await destroySsoSession(ctx, ssoSessionIdFromCookie, config, storage, isHttpsRequest)
			return null
		}

		if (authorization.max_age) {
			const now = Math.floor(Date.now() / 1000)
			if (now - ssoSessionData.auth_time > authorization.max_age) {
				await destroySsoSession(ctx, ssoSessionIdFromCookie, config, storage, isHttpsRequest)
				return null
			}
		}

		// Validate required OAuth parameters
		if (
			!authorization.client_id ||
			!authorization.redirect_uri ||
			!authorization.response_type
		) {
			throw new MissingParameterError("client_id, redirect_uri, or response_type")
		}

		// Client authorization check
		if (
			!(await allowFn(
				{
					clientID: authorization.client_id,
					redirectURI: authorization.redirect_uri,
					audience: authorization.audience
				},
				ctx.req.raw
			))
		) {
			if (authorization.prompt === "none") {
				const errorUrl = new URL(authorization.redirect_uri)
				errorUrl.searchParams.set("error", "unauthorized_client")
				if (authorization.state) errorUrl.searchParams.set("state", authorization.state)
				return ctx.redirect(errorUrl.toString(), 302)
			}
			throw new UnauthorizedClientError(authorization.client_id, authorization.redirect_uri)
		}

		// SSO flow will be handled by authorize handler
		// Return null to indicate SSO should continue with normal flow
		return null
	})
}
