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
 * @template TProperties - The strongly-typed properties from subject schemas
 */
export type ClaimsTransformFunction<TProperties = Record<string, unknown>> = (
	properties: TProperties,
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
 * @template TProperties - The strongly-typed properties from subject schemas
 */
export interface ClaimsConfiguration<TProperties = Record<string, unknown>> {
	/**
	 * Function to transform user properties into claims for tokens and UserInfo.
	 * This function is called for both ID tokens and UserInfo responses.
	 *
	 * @example With proper TypeScript autocomplete
	 * ```typescript
	 * // First define your subjects
	 * const subjects = createSubjects({
	 *   user: object({
	 *     userID: string(),
	 *     fullName: string(),
	 *     username: string(),
	 *     emailAddress: string(),
	 *     emailVerified: boolean(),
	 *     tenantId: optional(string()),
	 *     roles: optional(array(string()))
	 *   })
	 * })
	 *
	 * // Then use in issuer with full typing
	 * const app = issuer({
	 *   subjects,
	 *   claims: {
	 *     transform: async (properties, context) => {
	 *       const claims: Record<string, unknown> = {}
	 *
	 *       // properties is now fully typed - autocomplete works!
	 *       if (context.scopes.includes('profile')) {
	 *         claims.name = properties.fullName // ✅ TypeScript knows this exists
	 *         claims.preferred_username = properties.username // ✅ Autocomplete works
	 *       }
	 *
	 *       if (context.scopes.includes('email')) {
	 *         claims.email = properties.emailAddress // ✅ Type-safe
	 *         claims.email_verified = properties.emailVerified // ✅ Boolean type enforced
	 *       }
	 *
	 *       // Conditional claims with full type safety
	 *       if (context.clientID.startsWith('tenant_') && properties.tenantId) {
	 *         claims.tenant_id = properties.tenantId // ✅ Optional properly handled
	 *         claims.roles = properties.roles || [] // ✅ Array type preserved
	 *       }
	 *
	 *       return { claims, success: true }
	 *     }
	 *   }
	 * })
	 * ```
	 */
	transform?: ClaimsTransformFunction<TProperties>

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
	 * Default claims applied only when property doesn't exist in subject properties.
	 * These are true fallbacks that never override existing subject data.
	 *
	 * @example
	 * ```typescript
	 * defaults: {
	 *   name: 'Anonymous',      // Only if subject has no name
	 *   company: 'Acme Corp',   // Only if subject has no company
	 *   version: '1.0'          // Only if subject has no version
	 * }
	 * ```
	 */
	defaults?: Record<string, unknown>

	/**
	 * Override claims that always take precedence over subject properties.
	 * Useful for system metadata that should never be overridden by user data.
	 *
	 * @example
	 * ```typescript
	 * overrides: {
	 *   iss: 'https://auth.example.com',  // Always this issuer
	 *   system_version: '2.0',            // Always this version
	 *   environment: 'production'         // Always this environment
	 * }
	 * ```
	 */
	overrides?: Record<string, unknown>

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
 * @template TProperties - The strongly-typed properties from subject schemas
 * @param properties - Original properties object (strongly typed)
 * @param mapping - Mapping of property names to claim names
 * @returns Mapped claims object
 */
export const applyClaimsMapping = <TProperties = Record<string, unknown>>(
	properties: TProperties,
	mapping: Record<string, string>
): Record<string, unknown> => {
	const mappedClaims: Record<string, unknown> = {}

	for (const [propertyName, claimName] of Object.entries(mapping)) {
		if (propertyName in (properties as Record<string, unknown>)) {
			mappedClaims[claimName] = (properties as Record<string, unknown>)[propertyName]
		}
	}

	return mappedClaims
}

/**
 * Filters claims based on target (ID token vs UserInfo).
 * Removes claims that are restricted to specific targets.
 *
 * @template TProperties - The strongly-typed properties from subject schemas
 * @param claims - Claims object to filter
 * @param target - Target for the claims
 * @param config - Claims configuration with target restrictions
 * @returns Filtered claims object
 */
export const filterClaimsByTarget = <TProperties = Record<string, unknown>>(
	claims: Record<string, unknown>,
	target: "id_token" | "userinfo" | "access_token",
	config: ClaimsConfiguration<TProperties>
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
 * @template TProperties - The strongly-typed properties from subject schemas
 * @param properties - Original user properties (strongly typed)
 * @param context - Transform context
 * @param config - Claims configuration
 * @returns Promise resolving to transformed claims or null if validation fails
 */
export const transformClaims = async <TProperties = Record<string, unknown>>(
	properties: TProperties,
	context: ClaimsTransformContext,
	config: ClaimsConfiguration<TProperties>
): Promise<Record<string, unknown> | null> => {
	// Start with subject properties as base (authoritative data)
	let finalClaims: Record<string, unknown> = { ...(properties as Record<string, unknown>) }

	// Apply defaults only for missing properties (true fallbacks)
	const defaultsToApply = config.defaults || {}
	for (const [key, value] of Object.entries(defaultsToApply)) {
		if (finalClaims[key] === undefined) {
			finalClaims[key] = value
		}
	}

	// Apply simple mapping claims (merge with existing, mapping takes precedence)
	if (config.mapping) {
		const mappedClaims = applyClaimsMapping(properties, config.mapping)
		finalClaims = { ...finalClaims, ...mappedClaims }
	}

	// Apply overrides (always take precedence)
	if (config.overrides) {
		finalClaims = { ...finalClaims, ...config.overrides }
	}

	// Apply custom transform function (takes precedence for custom logic)
	if (config.transform) {
		try {
			const transformResult = await config.transform(properties, context)

			if (!transformResult.success) {
				console.error("Claims transformation failed:", transformResult.error)
				if (config.essential?.strict) {
					return null
				}
			} else {
				// Transform takes precedence for intentional customization
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
 * @template TProperties - The strongly-typed properties from subject schemas
 * @returns Default claims configuration with proper typing
 */
export const createDefaultClaimsConfig = <
	TProperties = Record<string, unknown>
>(): ClaimsConfiguration<TProperties> => {
	return {
		transform: (properties, context) => {
			const claims: Record<string, unknown> = {}
			const props = properties as Record<string, unknown>

			// Always include sub claim if available
			if ("sub" in props && props.sub) {
				claims.sub = props.sub
			}

			// Standard OIDC claims based on scopes
			if (context.scopes.includes("profile")) {
				if ("name" in props && props.name) claims.name = props.name
				if ("preferred_username" in props && props.preferred_username)
					claims.preferred_username = props.preferred_username
				if ("picture" in props && props.picture) claims.picture = props.picture
			}

			if (context.scopes.includes("email")) {
				if ("email" in props && props.email) claims.email = props.email
				if ("email_verified" in props && props.email_verified !== undefined)
					claims.email_verified = props.email_verified
			}

			return { claims, success: true }
		},
		essential: {
			required: ["sub"],
			strict: false
		}
	}
}
