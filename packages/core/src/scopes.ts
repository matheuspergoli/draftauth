/**
 * Utility functions for handling OAuth 2.0 scopes.
 * Scopes define the level of access that an application is requesting.
 */

/**
 * Parses scope values from various input formats into a consistent string array.
 * Handles both space-separated strings and arrays, filtering out empty values.
 *
 * @param scope - Scope input in string, array, or null/undefined format
 * @returns Array of non-empty scope strings
 *
 * @example
 * ```ts
 * parseScopes("openid profile email")
 * // Returns: ["openid", "profile", "email"]
 *
 * parseScopes(["openid", "", "profile"])
 * // Returns: ["openid", "profile"]
 *
 * parseScopes(null)
 * // Returns: []
 * ```
 */
export const parseScopes = (scope: string | string[] | null | undefined): string[] => {
	if (Array.isArray(scope)) {
		return scope.filter(Boolean)
	}
	return scope?.split(" ").filter(Boolean) ?? []
}

/**
 * Validates and filters requested scopes against authorized scopes.
 * Returns the intersection of requested scopes that are also present in the
 * originally authorized scopes, ensuring no scope escalation occurs.
 *
 * @param tokenReq - Scopes being requested in the current token request
 * @param authorizeReq - Scopes that were originally authorized during authorization
 * @returns Array of valid scopes that are both requested and authorized, or undefined if no validation needed
 *
 * @example
 * ```ts
 * // User authorized: ["openid", "profile", "email"]
 * // Token request asks for: "openid profile"
 * validateScopes("openid profile", ["openid", "profile", "email"])
 * // Returns: ["openid", "profile"]
 *
 * // Attempting scope escalation:
 * validateScopes("openid admin", ["openid", "profile"])
 * // Returns: ["openid"] (admin scope rejected)
 *
 * // No token request scopes specified:
 * validateScopes(null, ["openid", "profile"])
 * // Returns: ["openid", "profile"] (all authorized scopes)
 * ```
 */
export const validateScopes = (
	tokenReq?: string | null,
	authorizeReq?: string[]
): string[] | undefined => {
	if (!authorizeReq?.length || tokenReq === null || tokenReq === undefined) {
		return authorizeReq
	}

	const requestedScopes = new Set(parseScopes(tokenReq))
	const authorizedScopes = new Set(authorizeReq)

	return [...requestedScopes.intersection(authorizedScopes)]
}
