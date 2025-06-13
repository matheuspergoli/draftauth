/**
 * Claims configuration and transformation utilities for Draft Auth.
 * Handles custom claim mapping, validation, and transformation for OIDC compliance.
 *
 * This module implements the Phase 1 claims configuration as outlined in IMPROVEMENTS.md,
 * providing extensible claim transformation with multi-tenant support.
 */

/**
 * Context information available during claims transformation.
 * Provides the necessary context for making dynamic claim decisions.
 */
export interface ClaimsTransformContext {
	/** OAuth 2.0 client identifier requesting the claims */
	clientID: string
	/** OAuth 2.0 scopes requested by the client */
	scopes: string[]
	/** Optional audience parameter for the tokens */
	audience?: string
	/** Target for the claims: ID token, UserInfo endpoint, or access token */
	target: "id_token" | "userinfo" | "access_token"
	/** Issuer URL for claim context */
	issuer: string
	/** OIDC nonce if provided */
	nonce?: string
	/** OIDC session ID if available */
	sessionId?: string
	/** Authentication time for claim context */
	authTime?: number
}

/**
 * Result of claims transformation with optional validation.
 */
export interface ClaimsTransformResult {
	/** Transformed claims to include in the token/response */
	claims: Record<string, unknown>
	/** Whether the transformation was successful */
	success: boolean
	/** Error message if transformation failed */
	error?: string
}

/**
 * Function type for transforming user properties into claims.
 * Allows for dynamic, context-aware claim generation.
 */
export type ClaimsTransformFunction = (
	properties: Record<string, unknown>,
	context: ClaimsTransformContext
) => ClaimsTransformResult | Promise<ClaimsTransformResult>

/**
 * Configuration for essential claims validation.
 * Essential claims are required for successful authentication.
 */
export interface EssentialClaimsConfig {
	/** List of claim names that must be present */
	required: string[]
	/** Whether to fail authentication if essential claims are missing */
	strict: boolean
	/** Custom validation function for essential claims */
	validate?: (claims: Record<string, unknown>, context: ClaimsTransformContext) => boolean
}

/**
 * Comprehensive claims configuration for the Draft Auth issuer.
 * Supports both simple and advanced claim transformation scenarios.
 */
export interface ClaimsConfiguration {
	/**
	 * Function to transform user properties into claims for tokens and UserInfo.
	 * This function is called for both ID tokens and UserInfo responses.
	 *
	 * @example
	 * ```typescript
	 * transform: async (properties, context) => {
	 *   const claims: Record<string, unknown> = {}
	 *
	 *   // Add standard claims based on scopes
	 *   if (context.scopes.includes('profile')) {
	 *     claims.name = properties.fullName
	 *     claims.preferred_username = properties.username
	 *   }
	 *
	 *   if (context.scopes.includes('email')) {
	 *     claims.email = properties.emailAddress
	 *     claims.email_verified = properties.emailVerified
	 *   }
	 *
	 *   // Add tenant-specific claims
	 *   if (context.clientID.startsWith('tenant_')) {
	 *     claims.tenant_id = properties.tenantId
	 *     claims.roles = properties.roles
	 *   }
	 *
	 *   return { claims, success: true }
	 * }
	 * ```
	 */
	transform?: ClaimsTransformFunction

	/**
	 * Configuration for essential claims validation.
	 * Essential claims are required for successful authentication and must be present.
	 *
	 * @example
	 * ```typescript
	 * essential: {
	 *   required: ['sub', 'email'],
	 *   strict: true,
	 *   validate: (claims, context) => {
	 *     // Custom validation logic
	 *     return claims.email && typeof claims.email === 'string'
	 *   }
	 * }
	 * ```
	 */
	essential?: EssentialClaimsConfig

	/**
	 * Default claims to always include regardless of scopes.
	 * These claims will be merged with transformed claims.
	 *
	 * @example
	 * ```typescript
	 * defaults: {
	 *   iss: 'https://auth.example.com',
	 *   custom_namespace: 'draft-auth'
	 * }
	 * ```
	 */
	defaults?: Record<string, unknown>

	/**
	 * Mapping of property names to claim names.
	 * Useful for simple property renaming without custom transform functions.
	 *
	 * @example
	 * ```typescript
	 * mapping: {
	 *   'userEmail': 'email',
	 *   'fullName': 'name',
	 *   'avatarUrl': 'picture'
	 * }
	 * ```
	 */
	mapping?: Record<string, string>

	/**
	 * Claims that should only be included in ID tokens, not in UserInfo responses.
	 * Useful for claims that are sensitive or only needed during initial authentication.
	 */
	idTokenOnly?: string[]

	/**
	 * Claims that should only be included in UserInfo responses, not in ID tokens.
	 * Useful for large claims or claims that change frequently.
	 */
	userInfoOnly?: string[]
}

/**
 * Validates essential claims against the provided claims object.
 * Returns true if all essential claims are present and valid.
 *
 * @param claims - Claims object to validate
 * @param config - Essential claims configuration
 * @param context - Transform context for validation
 * @returns True if essential claims validation passes
 */
export const validateEssentialClaims = (
	claims: Record<string, unknown>,
	config: EssentialClaimsConfig,
	context: ClaimsTransformContext
): boolean => {
	// Check if all required claims are present
	const missingClaims = config.required.filter((claim) => !(claim in claims))

	if (missingClaims.length > 0) {
		if (config.strict) {
			return false
		}
		console.warn(`Missing essential claims: ${missingClaims.join(", ")}`)
	}

	// Run custom validation if provided
	if (config.validate) {
		try {
			return config.validate(claims, context)
		} catch (error) {
			console.error("Essential claims validation failed:", error)
			return false
		}
	}

	return true
}

/**
 * Applies simple property mapping to claims.
 * Maps property names to claim names based on the provided mapping.
 *
 * @param properties - Original properties object
 * @param mapping - Mapping of property names to claim names
 * @returns Mapped claims object
 */
export const applyClaimsMapping = (
	properties: Record<string, unknown>,
	mapping: Record<string, string>
): Record<string, unknown> => {
	const mappedClaims: Record<string, unknown> = {}

	for (const [propertyName, claimName] of Object.entries(mapping)) {
		if (propertyName in properties) {
			mappedClaims[claimName] = properties[propertyName]
		}
	}

	return mappedClaims
}

/**
 * Filters claims based on target (ID token vs UserInfo).
 * Removes claims that are restricted to specific targets.
 *
 * @param claims - Claims object to filter
 * @param target - Target for the claims
 * @param config - Claims configuration with target restrictions
 * @returns Filtered claims object
 */
export const filterClaimsByTarget = (
	claims: Record<string, unknown>,
	target: "id_token" | "userinfo" | "access_token",
	config: ClaimsConfiguration
): Record<string, unknown> => {
	const filteredClaims = { ...claims }

	if (target === "id_token" && config.userInfoOnly) {
		for (const claim of config.userInfoOnly) {
			delete filteredClaims[claim]
		}
	}

	if (target === "userinfo" && config.idTokenOnly) {
		for (const claim of config.idTokenOnly) {
			delete filteredClaims[claim]
		}
	}

	return filteredClaims
}

/**
 * Main function to transform user properties into claims.
 * Applies all configured transformations, mappings, and validations.
 *
 * @param properties - Original user properties
 * @param context - Transform context
 * @param config - Claims configuration
 * @returns Promise resolving to transformed claims or null if validation fails
 */
export const transformClaims = async (
	properties: Record<string, unknown>,
	context: ClaimsTransformContext,
	config: ClaimsConfiguration
): Promise<Record<string, unknown> | null> => {
	let finalClaims: Record<string, unknown> = {}

	// Start with default claims
	if (config.defaults) {
		finalClaims = { ...config.defaults }
	}

	// Apply simple mapping if provided
	if (config.mapping) {
		const mappedClaims = applyClaimsMapping(properties, config.mapping)
		finalClaims = { ...finalClaims, ...mappedClaims }
	}

	// Apply custom transform function if provided
	if (config.transform) {
		try {
			const transformResult = await config.transform(properties, context)

			if (!transformResult.success) {
				console.error("Claims transformation failed:", transformResult.error)
				if (config.essential?.strict) {
					return null
				}
			} else {
				finalClaims = { ...finalClaims, ...transformResult.claims }
			}
		} catch (error) {
			console.error("Claims transformation threw error:", error)
			if (config.essential?.strict) {
				return null
			}
		}
	}

	// Filter claims based on target
	finalClaims = filterClaimsByTarget(finalClaims, context.target, config)

	// Validate essential claims
	if (config.essential) {
		const isValid = validateEssentialClaims(finalClaims, config.essential, context)
		if (!isValid && config.essential.strict) {
			return null
		}
	}

	return finalClaims
}

/**
 * Creates a default claims configuration with standard OIDC behavior.
 * Useful as a starting point or fallback configuration.
 *
 * @returns Default claims configuration
 */
export const createDefaultClaimsConfig = (): ClaimsConfiguration => {
	return {
		transform: (properties, context) => {
			const claims: Record<string, unknown> = {}

			// Always include sub claim if available
			if (properties.sub) {
				claims.sub = properties.sub
			}

			// Standard OIDC claims based on scopes
			if (context.scopes.includes("profile")) {
				if (properties.name) claims.name = properties.name
				if (properties.preferred_username)
					claims.preferred_username = properties.preferred_username
				if (properties.picture) claims.picture = properties.picture
			}

			if (context.scopes.includes("email")) {
				if (properties.email) claims.email = properties.email
				if (properties.email_verified !== undefined)
					claims.email_verified = properties.email_verified
			}

			return { claims, success: true }
		},
		essential: {
			required: ["sub"],
			strict: false
		}
	}
}
