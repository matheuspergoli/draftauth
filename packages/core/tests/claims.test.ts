/**
 * Claims configuration and transformation tests
 */
import { describe, expect, it } from "vitest"
import {
	applyClaimsMapping,
	type ClaimsConfiguration,
	type ClaimsTransformContext,
	createDefaultClaimsConfig,
	type EssentialClaimsConfig,
	filterClaimsByTarget,
	transformClaims,
	validateEssentialClaims
} from "../src/claims"

describe("Claims Functions", () => {
	const createMockContext = (
		overrides?: Partial<ClaimsTransformContext>
	): ClaimsTransformContext => ({
		clientID: "test-client",
		scopes: ["openid", "profile", "email"],
		target: "id_token",
		issuer: "https://auth.example.com",
		...overrides
	})

	describe("validateEssentialClaims", () => {
		it("should validate required claims presence", () => {
			const claims = { sub: "user123", email: "test@example.com", name: "Test User" }
			const config: EssentialClaimsConfig = {
				required: ["sub", "email"],
				strict: true
			}
			const context = createMockContext()

			const result = validateEssentialClaims(claims, config, context)

			expect(result.success).toBe(true)
			expect(result.missing).toEqual([])
		})

		it("should detect missing required claims", () => {
			const claims = { sub: "user123" }
			const config: EssentialClaimsConfig = {
				required: ["sub", "email", "name"],
				strict: true
			}
			const context = createMockContext()

			const result = validateEssentialClaims(claims, config, context)

			expect(result.success).toBe(false)
			expect(result.missing).toEqual(["email", "name"])
		})

		it("should run custom validation", () => {
			const claims = { sub: "user123", email: "test@example.com" }
			const config: EssentialClaimsConfig = {
				required: ["sub"],
				strict: true,
				validate: (claims) => {
					return typeof claims.email === "string" && claims.email.includes("@")
				}
			}
			const context = createMockContext()

			const result = validateEssentialClaims(claims, config, context)

			expect(result.success).toBe(true)
		})

		it("should fail custom validation", () => {
			const claims = { sub: "user123", email: "invalid-email" }
			const config: EssentialClaimsConfig = {
				required: ["sub"],
				strict: true,
				validate: (claims) => {
					return typeof claims.email === "string" && claims.email.includes("@")
				}
			}
			const context = createMockContext()

			const result = validateEssentialClaims(claims, config, context)

			expect(result.success).toBe(false)
			expect(result.missing).toEqual(["custom_validation_failed"])
		})

		it("should handle validation exceptions", () => {
			const claims = { sub: "user123" }
			const config: EssentialClaimsConfig = {
				required: ["sub"],
				strict: true,
				validate: () => {
					throw new Error("Validation error")
				}
			}
			const context = createMockContext()

			const result = validateEssentialClaims(claims, config, context)

			expect(result.success).toBe(false)
			expect(result.missing).toEqual(["custom_validation_exception"])
		})
	})

	describe("applyClaimsMapping", () => {
		it("should map property names to claim names", () => {
			const properties = {
				userEmail: "test@example.com",
				fullName: "Test User",
				avatarUrl: "https://example.com/avatar.jpg",
				userId: "123"
			}
			const mapping = {
				userEmail: "email",
				fullName: "name",
				avatarUrl: "picture"
			}

			const result = applyClaimsMapping(properties, mapping)

			expect(result).toEqual({
				email: "test@example.com",
				name: "Test User",
				picture: "https://example.com/avatar.jpg"
			})
		})

		it("should skip missing properties", () => {
			const properties = {
				userEmail: "test@example.com"
			}
			const mapping = {
				userEmail: "email",
				fullName: "name",
				avatarUrl: "picture"
			}

			const result = applyClaimsMapping(properties, mapping)

			expect(result).toEqual({
				email: "test@example.com"
			})
		})

		it("should handle empty mapping", () => {
			const properties = { name: "Test User" }
			const mapping = {}

			const result = applyClaimsMapping(properties, mapping)

			expect(result).toEqual({})
		})
	})

	describe("filterClaimsByTarget", () => {
		const claims = {
			sub: "user123",
			name: "Test User",
			email: "test@example.com",
			sensitive_data: "secret",
			large_data: "large payload"
		}

		it("should filter userInfo-only claims from ID token", () => {
			const config: ClaimsConfiguration = {
				userInfoOnly: ["large_data", "sensitive_data"]
			}

			const result = filterClaimsByTarget(claims, "id_token", config)

			expect(result).toEqual({
				sub: "user123",
				name: "Test User",
				email: "test@example.com"
			})
		})

		it("should filter ID token-only claims from UserInfo", () => {
			const config: ClaimsConfiguration = {
				idTokenOnly: ["sensitive_data"]
			}

			const result = filterClaimsByTarget(claims, "userinfo", config)

			expect(result).toEqual({
				sub: "user123",
				name: "Test User",
				email: "test@example.com",
				large_data: "large payload"
			})
		})

		it("should not filter claims for access tokens", () => {
			const config: ClaimsConfiguration = {
				idTokenOnly: ["sensitive_data"],
				userInfoOnly: ["large_data"]
			}

			const result = filterClaimsByTarget(claims, "access_token", config)

			expect(result).toEqual(claims)
		})

		it("should handle missing filter configuration", () => {
			const config: ClaimsConfiguration = {}

			const result = filterClaimsByTarget(claims, "id_token", config)

			expect(result).toEqual(claims)
		})
	})

	describe("transformClaims", () => {
		it("should apply all transformations in correct order", async () => {
			const properties = {
				userId: "123",
				userEmail: "test@example.com",
				fullName: "Test User"
			}

			const config: ClaimsConfiguration = {
				defaults: {
					email_verified: false,
					default_role: "user"
				},
				mapping: {
					userEmail: "email",
					fullName: "name"
				},
				overrides: {
					iss: "https://auth.example.com",
					aud: "test-client"
				},
				transform: (_props, context) => ({
					claims: {
						custom_claim: "custom_value",
						client_info: context.clientID
					},
					success: true
				})
			}

			const context = createMockContext()
			const result = await transformClaims(properties, context, config)

			expect(result).toEqual({
				userId: "123",
				userEmail: "test@example.com",
				fullName: "Test User",
				email_verified: false,
				default_role: "user",
				email: "test@example.com",
				name: "Test User",
				iss: "https://auth.example.com",
				aud: "test-client",
				custom_claim: "custom_value",
				client_info: "test-client"
			})
		})

		it("should apply defaults only for missing properties", async () => {
			const properties = {
				name: "Existing Name",
				email: "test@example.com"
			}

			const config: ClaimsConfiguration = {
				defaults: {
					name: "Default Name",
					role: "default_role"
				}
			}

			const context = createMockContext()
			const result = await transformClaims(properties, context, config)

			expect(result).toEqual({
				name: "Existing Name",
				email: "test@example.com",
				role: "default_role"
			})
		})

		it("should filter claims by target", async () => {
			const properties = { name: "Test User" }
			const config: ClaimsConfiguration = {
				transform: () => ({
					claims: {
						id_token_only: "secret",
						userinfo_only: "large_data",
						common: "shared"
					},
					success: true
				}),
				idTokenOnly: ["id_token_only"],
				userInfoOnly: ["userinfo_only"]
			}

			const idTokenContext = createMockContext({ target: "id_token" })
			const userInfoContext = createMockContext({ target: "userinfo" })

			const idTokenResult = await transformClaims(properties, idTokenContext, config)
			const userInfoResult = await transformClaims(properties, userInfoContext, config)

			expect(idTokenResult).toEqual({
				name: "Test User",
				id_token_only: "secret",
				common: "shared"
			})

			expect(userInfoResult).toEqual({
				name: "Test User",
				userinfo_only: "large_data",
				common: "shared"
			})
		})

		it("should handle failed transform in strict mode", async () => {
			const properties = { name: "Test User" }
			const config: ClaimsConfiguration = {
				transform: () => ({
					claims: {},
					success: false,
					error: "Transform failed"
				}),
				essential: {
					required: ["sub"],
					strict: true
				}
			}

			const context = createMockContext()
			const result = await transformClaims(properties, context, config)

			expect(result).toBeNull()
		})

		it("should handle transform exceptions in strict mode", async () => {
			const properties = { name: "Test User" }
			const config: ClaimsConfiguration = {
				transform: () => {
					throw new Error("Transform error")
				},
				essential: {
					required: ["sub"],
					strict: true
				}
			}

			const context = createMockContext()
			const result = await transformClaims(properties, context, config)

			expect(result).toBeNull()
		})

		it("should handle essential claims validation failure", async () => {
			const properties = { name: "Test User" }
			const config: ClaimsConfiguration = {
				essential: {
					required: ["sub", "email"],
					strict: true
				}
			}

			const context = createMockContext()
			const result = await transformClaims(properties, context, config)

			expect(result).toBeNull()
		})

		it("should continue with non-strict essential claims validation", async () => {
			const properties = { name: "Test User" }
			const config: ClaimsConfiguration = {
				essential: {
					required: ["sub", "email"],
					strict: false
				}
			}

			const context = createMockContext()
			const result = await transformClaims(properties, context, config)

			expect(result).toEqual({ name: "Test User" })
		})
	})

	describe("createDefaultClaimsConfig", () => {
		it("should create default configuration", () => {
			const config = createDefaultClaimsConfig()

			expect(config.transform).toBeDefined()
			expect(config.essential).toEqual({
				required: [],
				strict: false
			})
		})

		it("should transform standard OIDC claims based on scopes", async () => {
			const config = createDefaultClaimsConfig()
			const properties = {
				name: "Test User",
				preferred_username: "testuser",
				picture: "https://example.com/avatar.jpg",
				email: "test@example.com",
				email_verified: true
			}

			const profileContext = createMockContext({ scopes: ["openid", "profile"] })
			const emailContext = createMockContext({ scopes: ["openid", "email"] })
			const bothContext = createMockContext({ scopes: ["openid", "profile", "email"] })

			const profileResult = await Promise.resolve(
				config.transform!(properties, profileContext)
			)
			const emailResult = await Promise.resolve(config.transform!(properties, emailContext))
			const bothResult = await Promise.resolve(config.transform!(properties, bothContext))

			expect(profileResult.claims).toEqual({
				name: "Test User",
				preferred_username: "testuser",
				picture: "https://example.com/avatar.jpg"
			})

			expect(emailResult.claims).toEqual({
				email: "test@example.com",
				email_verified: true
			})

			expect(bothResult.claims).toEqual({
				name: "Test User",
				preferred_username: "testuser",
				picture: "https://example.com/avatar.jpg",
				email: "test@example.com",
				email_verified: true
			})
		})

		it("should handle missing properties gracefully", async () => {
			const config = createDefaultClaimsConfig()
			const properties = {
				name: "Test User"
			}

			const context = createMockContext({ scopes: ["openid", "profile", "email"] })
			const result = await Promise.resolve(config.transform!(properties, context))

			expect(result.claims).toEqual({
				name: "Test User"
			})
			expect(result.success).toBe(true)
		})

		it("should handle falsy values correctly", async () => {
			const config = createDefaultClaimsConfig()
			const properties = {
				name: "",
				email_verified: false,
				picture: null
			}

			const context = createMockContext({ scopes: ["openid", "profile", "email"] })
			const result = await Promise.resolve(config.transform!(properties, context))

			expect(result.claims).toEqual({
				email_verified: false
			})
		})
	})

	describe("Integration Scenarios", () => {
		it("should handle multi-tenant claims transformation", async () => {
			const properties = {
				id: "user123",
				name: "Test User",
				email: "test@tenant1.com",
				tenantId: "tenant1",
				roles: ["user", "admin"]
			}

			const config: ClaimsConfiguration = {
				transform: (props, context) => {
					const claims: Record<string, unknown> = {}
					const typedProps = props as typeof properties

					if (context.scopes.includes("profile")) {
						claims.name = typedProps.name
					}

					if (context.scopes.includes("email")) {
						claims.email = typedProps.email
					}

					// Tenant-specific claims
					if (context.clientID.startsWith("tenant_")) {
						claims.tenant_id = typedProps.tenantId
						claims.roles = typedProps.roles
					}

					return { claims, success: true }
				}
			}

			const tenantContext = createMockContext({
				clientID: "tenant_admin_app",
				scopes: ["openid", "profile", "email"]
			})

			const publicContext = createMockContext({
				clientID: "public_app",
				scopes: ["openid", "profile", "email"]
			})

			const tenantResult = await transformClaims(properties, tenantContext, config)
			const publicResult = await transformClaims(properties, publicContext, config)

			expect(tenantResult).toEqual({
				id: "user123",
				name: "Test User",
				email: "test@tenant1.com",
				tenantId: "tenant1",
				roles: ["user", "admin"],
				tenant_id: "tenant1"
			})

			expect(publicResult).toEqual({
				id: "user123",
				name: "Test User",
				email: "test@tenant1.com",
				tenantId: "tenant1",
				roles: ["user", "admin"]
			})
		})

		it("should handle complex scope-based transformations", async () => {
			const properties = {
				id: "user123",
				firstName: "John",
				lastName: "Doe",
				email: "john@example.com",
				phone: "+1234567890",
				address: {
					street: "123 Main St",
					city: "Anytown",
					country: "US"
				}
			}

			const config: ClaimsConfiguration = {
				transform: (props, context) => {
					const claims: Record<string, unknown> = {}
					const typedProps = props as typeof properties

					if (context.scopes.includes("profile")) {
						claims.name = `${typedProps.firstName} ${typedProps.lastName}`
						claims.given_name = typedProps.firstName
						claims.family_name = typedProps.lastName
					}

					if (context.scopes.includes("email")) {
						claims.email = typedProps.email
						claims.email_verified = true
					}

					if (context.scopes.includes("phone")) {
						claims.phone_number = typedProps.phone
						claims.phone_number_verified = false
					}

					if (context.scopes.includes("address")) {
						claims.address = typedProps.address
					}

					return { claims, success: true }
				}
			}

			const fullContext = createMockContext({
				scopes: ["openid", "profile", "email", "phone", "address"]
			})

			const limitedContext = createMockContext({
				scopes: ["openid", "profile"]
			})

			const fullResult = await transformClaims(properties, fullContext, config)
			const limitedResult = await transformClaims(properties, limitedContext, config)

			expect(fullResult).toMatchObject({
				name: "John Doe",
				given_name: "John",
				family_name: "Doe",
				email: "john@example.com",
				email_verified: true,
				phone_number: "+1234567890",
				phone_number_verified: false,
				address: {
					street: "123 Main St",
					city: "Anytown",
					country: "US"
				}
			})

			expect(limitedResult).toMatchObject({
				name: "John Doe",
				given_name: "John",
				family_name: "Doe"
			})
			// Original properties are preserved, transform only adds scope-specific claims
			expect(limitedResult).toHaveProperty("email") // Original property preserved
			expect(limitedResult).toHaveProperty("phone") // Original property preserved
			expect(limitedResult).toHaveProperty("address") // Original property preserved
			// But scope-specific transformed claims are not added
			expect(limitedResult).not.toHaveProperty("email_verified")
			expect(limitedResult).not.toHaveProperty("phone_number")
			expect(limitedResult).not.toHaveProperty("phone_number_verified")
		})
	})

	describe("Error Handling", () => {
		it("should handle async transform functions", async () => {
			const properties = { name: "Test User" }
			const config: ClaimsConfiguration = {
				transform: async () => {
					await new Promise((resolve) => setTimeout(resolve, 1))
					return {
						claims: { async_claim: "processed" },
						success: true
					}
				}
			}

			const context = createMockContext()
			const result = await transformClaims(properties, context, config)

			expect(result).toEqual({
				name: "Test User",
				async_claim: "processed"
			})
		})

		it("should handle async transform failures", async () => {
			const properties = { name: "Test User" }
			const config: ClaimsConfiguration = {
				transform: async () => {
					await new Promise((resolve) => setTimeout(resolve, 1))
					throw new Error("Async error")
				},
				essential: { required: [], strict: false }
			}

			const context = createMockContext()
			const result = await transformClaims(properties, context, config)

			expect(result).toEqual({ name: "Test User" })
		})
	})
})
