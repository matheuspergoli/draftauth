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

const createMockContext = (): ClaimsTransformContext => ({
	clientID: "test-client",
	scopes: ["openid", "profile", "email"],
	target: "id_token",
	issuer: "https://auth.example.com"
})

describe("Claims utilities", () => {
	describe("validateEssentialClaims", () => {
		it("should pass validation with required claims present", () => {
			const claims = { sub: "user123", email: "test@example.com" }
			const config: EssentialClaimsConfig = {
				required: ["sub", "email"],
				strict: true
			}
			const context = createMockContext()

			const result = validateEssentialClaims(claims, config, context)

			expect(result.success).toBe(true)
			expect(result.missing).toEqual([])
		})

		it("should fail validation with missing required claims", () => {
			const claims = { sub: "user123" }
			const config: EssentialClaimsConfig = {
				required: ["sub", "email"],
				strict: true
			}
			const context = createMockContext()

			const result = validateEssentialClaims(claims, config, context)

			expect(result.success).toBe(false)
			expect(result.missing).toEqual(["email"])
		})

		it("should run custom validation function", () => {
			const claims = { sub: "user123", email: "test@example.com" }
			const config: EssentialClaimsConfig = {
				required: ["sub"],
				strict: true,
				validate: (claims) => claims.email === "test@example.com"
			}
			const context = createMockContext()

			const result = validateEssentialClaims(claims, config, context)

			expect(result.success).toBe(true)
			expect(result.missing).toEqual([])
		})

		it("should fail custom validation", () => {
			const claims = { sub: "user123", email: "wrong@example.com" }
			const config: EssentialClaimsConfig = {
				required: ["sub"],
				strict: true,
				validate: (claims) => claims.email === "test@example.com"
			}
			const context = createMockContext()

			const result = validateEssentialClaims(claims, config, context)

			expect(result.success).toBe(false)
			expect(result.missing).toEqual(["custom_validation_failed"])
		})

		it("should handle validation function exceptions", () => {
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
		it("should map property names to claim names and return properties to remove", () => {
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

			expect(result.mappedClaims).toEqual({
				email: "test@example.com",
				name: "Test User",
				picture: "https://example.com/avatar.jpg"
			})
			expect(result.propertiesToRemove).toEqual(["userEmail", "fullName", "avatarUrl"])
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

			expect(result.mappedClaims).toEqual({
				email: "test@example.com"
			})
			expect(result.propertiesToRemove).toEqual(["userEmail"])
		})

		it("should handle empty mapping", () => {
			const properties = { name: "Test User" }
			const mapping = {}

			const result = applyClaimsMapping(properties, mapping)

			expect(result.mappedClaims).toEqual({})
			expect(result.propertiesToRemove).toEqual([])
		})

		it("should correctly rename claims (no duplication)", () => {
			const properties = {
				email: "user@example.com",
				name: "John Doe"
			}
			const mapping = {
				email: "zapeada"
			}

			const result = applyClaimsMapping(properties, mapping)

			expect(result.mappedClaims).toEqual({
				zapeada: "user@example.com"
			})
			expect(result.propertiesToRemove).toEqual(["email"])
			// Ensure original property name is in the removal list
			expect(result.propertiesToRemove).toContain("email")
		})
	})

	describe("filterClaimsByTarget", () => {
		const claims = {
			sub: "user123",
			email: "test@example.com",
			sensitive_data: "secret",
			large_data: "very large data"
		}

		it("should filter out userInfoOnly claims for id_token", () => {
			const config: ClaimsConfiguration = {
				userInfoOnly: ["large_data"]
			}

			const result = filterClaimsByTarget(claims, "id_token", config)

			expect(result).toEqual({
				sub: "user123",
				email: "test@example.com",
				sensitive_data: "secret"
			})
		})

		it("should filter out idTokenOnly claims for userinfo", () => {
			const config: ClaimsConfiguration = {
				idTokenOnly: ["sensitive_data"]
			}

			const result = filterClaimsByTarget(claims, "userinfo", config)

			expect(result).toEqual({
				sub: "user123",
				email: "test@example.com",
				large_data: "very large data"
			})
		})

		it("should not filter claims for access_token", () => {
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
		it("should apply all transformations in correct order with proper mapping", async () => {
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
				// userEmail and fullName should be removed due to mapping
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

		it("should handle failed transform function", async () => {
			const properties = { name: "Test User" }
			const config: ClaimsConfiguration = {
				transform: () => ({
					claims: {},
					success: false,
					error: "Transform failed"
				}),
				essential: {
					required: [],
					strict: true
				}
			}

			const context = createMockContext()
			const result = await transformClaims(properties, context, config)

			expect(result).toBeNull()
		})

		it("should handle transform function exceptions", async () => {
			const properties = { name: "Test User" }
			const config: ClaimsConfiguration = {
				transform: () => {
					throw new Error("Transform error")
				},
				essential: {
					required: [],
					strict: true
				}
			}

			const context = createMockContext()
			const result = await transformClaims(properties, context, config)

			expect(result).toBeNull()
		})

		it("should filter claims by target", async () => {
			const properties = { name: "Test User" }
			const config: ClaimsConfiguration = {
				idTokenOnly: ["sensitive_claim"],
				userInfoOnly: ["large_claim"],
				transform: () => ({
					claims: {
						sensitive_claim: "secret",
						large_claim: "large data",
						normal_claim: "normal"
					},
					success: true
				})
			}

			const context = { ...createMockContext(), target: "userinfo" as const }
			const result = await transformClaims(properties, context, config)

			expect(result).toEqual({
				name: "Test User",
				large_claim: "large data",
				normal_claim: "normal"
			})
		})

		it("should validate essential claims in strict mode", async () => {
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

		it("should demonstrate correct mapping behavior - renaming not duplicating", async () => {
			const properties = {
				email: "user@example.com",
				name: "John Doe"
			}

			const config: ClaimsConfiguration = {
				mapping: {
					email: "zapeada"
				}
			}

			const context = createMockContext()
			const result = await transformClaims(properties, context, config)

			expect(result).toEqual({
				name: "John Doe",
				zapeada: "user@example.com"
				// email should NOT be present - it was renamed to zapeada
			})
			expect(result).not.toHaveProperty("email")
		})
	})

	describe("createDefaultClaimsConfig", () => {
		it("should create a valid default configuration", () => {
			const config = createDefaultClaimsConfig()

			expect(config.transform).toBeDefined()
			expect(config.essential).toBeDefined()
			expect(config.essential?.required).toEqual([])
			expect(config.essential?.strict).toBe(false)
		})

		it("should handle profile scope in default transform", async () => {
			const config = createDefaultClaimsConfig()
			const properties = {
				name: "Test User",
				preferred_username: "testuser",
				picture: "https://example.com/avatar.jpg"
			}
			const context = createMockContext()

			const result = await config.transform?.(properties, context)

			expect(result?.success).toBe(true)
			expect(result?.claims).toEqual({
				name: "Test User",
				preferred_username: "testuser",
				picture: "https://example.com/avatar.jpg"
			})
		})

		it("should handle email scope in default transform", async () => {
			const config = createDefaultClaimsConfig()
			const properties = {
				email: "test@example.com",
				email_verified: true
			}
			const context = { ...createMockContext(), scopes: ["openid", "email"] }

			const result = await config.transform?.(properties, context)

			expect(result?.success).toBe(true)
			expect(result?.claims).toEqual({
				email: "test@example.com",
				email_verified: true
			})
		})
	})
})
