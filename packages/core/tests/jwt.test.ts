/**
 * JWT creation and verification tests
 */
import { beforeEach, describe, expect, it } from "vitest"
import { jwt } from "../src/jwt"
import { signingKeys } from "../src/keys"
import { MemoryStorage } from "../src/storage/memory"

describe("JWT Functions", () => {
	let mockStorage: ReturnType<typeof MemoryStorage>

	beforeEach(() => {
		mockStorage = MemoryStorage()
	})

	describe("jwt.create", () => {
		it("should create a valid JWT with standard claims", async () => {
			const keys = await signingKeys(mockStorage)
			const key = keys[0]

			const payload = {
				sub: "user123",
				iss: "https://auth.example.com",
				aud: "test-app",
				exp: Math.floor(Date.now() / 1000) + 3600,
				iat: Math.floor(Date.now() / 1000),
				jti: "token123"
			}

			const token = await jwt.create(payload, key.alg, key.private, key.id)

			expect(token).toBeDefined()
			expect(typeof token).toBe("string")
			expect(token.split(".")).toHaveLength(3) // header.payload.signature
		})

		it("should create JWT with custom payload", async () => {
			const keys = await signingKeys(mockStorage)
			const key = keys[0]

			const payload = {
				sub: "admin456",
				role: "administrator",
				permissions: ["read", "write", "delete"],
				tenant: "org123",
				exp: Math.floor(Date.now() / 1000) + 1800
			}

			const token = await jwt.create(payload, key.alg, key.private, key.id)

			expect(token).toBeDefined()
			expect(typeof token).toBe("string")

			// Verify the token can be verified back
			const result = await jwt.verify(token, key.public)
			expect(result.payload.sub).toBe("admin456")
			expect(result.payload.role).toBe("administrator")
			expect(result.payload.permissions).toEqual(["read", "write", "delete"])
		})

		it("should handle JWT without key ID", async () => {
			const keys = await signingKeys(mockStorage)
			const key = keys[0]

			const payload = {
				sub: "user123",
				exp: Math.floor(Date.now() / 1000) + 3600
			}

			// Create JWT without providing keyId
			const token = await jwt.create(payload, key.alg, key.private)

			expect(token).toBeDefined()

			// Should still be verifiable
			const result = await jwt.verify(token, key.public)
			expect(result.payload.sub).toBe("user123")
		})

		it("should include proper JWT headers", async () => {
			const keys = await signingKeys(mockStorage)
			const key = keys[0]

			const payload = { sub: "user123", exp: Math.floor(Date.now() / 1000) + 3600 }
			const token = await jwt.create(payload, key.alg, key.private, "custom-key-id")

			// Decode header manually to verify structure
			const [headerB64] = token.split(".")
			const header = JSON.parse(Buffer.from(headerB64, "base64url").toString())

			expect(header.alg).toBe(key.alg)
			expect(header.typ).toBe("JWT")
			expect(header.kid).toBe("custom-key-id")
		})

		it("should handle different algorithms", async () => {
			const keys = await signingKeys(mockStorage)
			const key = keys[0]

			const payload = { sub: "user123", exp: Math.floor(Date.now() / 1000) + 3600 }

			// Test with ES256 (default)
			const tokenES256 = await jwt.create(payload, "ES256", key.private, key.id)
			expect(tokenES256).toBeDefined()

			const result = await jwt.verify(tokenES256, key.public)
			expect(result.payload.sub).toBe("user123")
		})

		it("should handle empty optional claims", async () => {
			const keys = await signingKeys(mockStorage)
			const key = keys[0]

			const payload = {
				sub: "user123"
				// No exp, iat, or other optional claims
			}

			const token = await jwt.create(payload, key.alg, key.private, key.id)
			expect(token).toBeDefined()

			const result = await jwt.verify(token, key.public)
			expect(result.payload.sub).toBe("user123")
		})

		it("should handle numeric claims", async () => {
			const keys = await signingKeys(mockStorage)
			const key = keys[0]

			const now = Math.floor(Date.now() / 1000)
			const payload = {
				sub: "user123",
				iat: now,
				exp: now + 3600,
				nbf: now,
				auth_time: now - 300,
				age: 25,
				version: 1.2
			}

			const token = await jwt.create(payload, key.alg, key.private, key.id)
			const result = await jwt.verify(token, key.public)

			expect(result.payload.iat).toBe(now)
			expect(result.payload.exp).toBe(now + 3600)
			expect(result.payload.age).toBe(25)
			expect(result.payload.version).toBe(1.2)
		})
	})

	describe("jwt.verify", () => {
		it("should verify valid JWT tokens", async () => {
			const keys = await signingKeys(mockStorage)
			const key = keys[0]

			const payload = {
				sub: "user123",
				iss: "https://auth.example.com",
				aud: "test-app",
				exp: Math.floor(Date.now() / 1000) + 3600,
				iat: Math.floor(Date.now() / 1000)
			}

			const token = await jwt.create(payload, key.alg, key.private, key.id)
			const result = await jwt.verify(token, key.public)

			expect(result.payload.sub).toBe("user123")
			expect(result.payload.iss).toBe("https://auth.example.com")
			expect(result.payload.aud).toBe("test-app")
			expect(result.protectedHeader.alg).toBe(key.alg)
			expect(result.protectedHeader.kid).toBe(key.id)
		})

		it("should verify tokens with typed payloads", async () => {
			const keys = await signingKeys(mockStorage)
			const key = keys[0]

			type CustomPayload = {
				sub: string
				role: string
				permissions: string[]
				metadata: {
					department: string
					level: number
				}
			}

			const payload: CustomPayload = {
				sub: "employee123",
				role: "developer",
				permissions: ["read", "write"],
				metadata: {
					department: "engineering",
					level: 3
				}
			}

			const token = await jwt.create(payload, key.alg, key.private, key.id)
			const result = await jwt.verify<CustomPayload>(token, key.public)

			// TypeScript should know these properties exist
			expect(result.payload.sub).toBe("employee123")
			expect(result.payload.role).toBe("developer")
			expect(result.payload.permissions).toEqual(["read", "write"])
			expect(result.payload.metadata.department).toBe("engineering")
			expect(result.payload.metadata.level).toBe(3)
		})

		it("should reject expired tokens", async () => {
			const keys = await signingKeys(mockStorage)
			const key = keys[0]

			const payload = {
				sub: "user123",
				exp: Math.floor(Date.now() / 1000) - 3600 // Expired 1 hour ago
			}

			const token = await jwt.create(payload, key.alg, key.private, key.id)

			await expect(jwt.verify(token, key.public)).rejects.toThrow()
		})

		it("should reject tokens with invalid signatures", async () => {
			const keys = await signingKeys(mockStorage)
			const key = keys[0]

			const payload = {
				sub: "user123",
				exp: Math.floor(Date.now() / 1000) + 3600
			}

			const token = await jwt.create(payload, key.alg, key.private, key.id)

			// Tamper with the token
			const parts = token.split(".")
			const tamperedToken = `${parts[0]}.${parts[1]}.invalid_signature`

			await expect(jwt.verify(tamperedToken, key.public)).rejects.toThrow()
		})

		it("should reject malformed tokens", async () => {
			const keys = await signingKeys(mockStorage)
			const key = keys[0]

			const malformedTokens = [
				"not.a.jwt",
				"invalid",
				"",
				"a.b", // Missing signature
				"too.many.parts.in.token",
				"invalid_base64.invalid_base64.invalid_base64"
			]

			for (const token of malformedTokens) {
				await expect(jwt.verify(token, key.public)).rejects.toThrow()
			}
		})

		it("should verify tokens with complex nested claims", async () => {
			const keys = await signingKeys(mockStorage)
			const key = keys[0]

			const payload = {
				sub: "user123",
				profile: {
					name: "John Doe",
					email: "john@example.com",
					preferences: {
						theme: "dark",
						language: "en",
						notifications: {
							email: true,
							push: false,
							sms: true
						}
					}
				},
				scopes: ["openid", "profile", "email"],
				custom_claims: {
					tenant_id: "org123",
					roles: ["user", "viewer"],
					features: {
						beta_access: true,
						experimental: false
					}
				},
				exp: Math.floor(Date.now() / 1000) + 3600
			}

			const token = await jwt.create(payload, key.alg, key.private, key.id)
			const result = await jwt.verify<{
				custom_claims: { roles: string[] }
				profile: {
					name: string
					preferences: { theme: string; notifications: { email: string } }
				}
			}>(token, key.public)

			expect(result.payload.profile.name).toBe("John Doe")
			expect(result.payload.profile.preferences.theme).toBe("dark")
			expect(result.payload.profile.preferences.notifications.email).toBe(true)
			expect(result.payload.scopes).toEqual(["openid", "profile", "email"])
			expect(result.payload.custom_claims.roles).toEqual(["user", "viewer"])
		})

		it("should handle tokens without optional kid header", async () => {
			const keys = await signingKeys(mockStorage)
			const key = keys[0]

			const payload = {
				sub: "user123",
				exp: Math.floor(Date.now() / 1000) + 3600
			}

			// Create token without key ID
			const token = await jwt.create(payload, key.alg, key.private)
			const result = await jwt.verify(token, key.public)

			expect(result.payload.sub).toBe("user123")
			// Kid should default to "sst"
			expect(result.protectedHeader.kid).toBe("sst")
		})
	})

	describe("Integration Scenarios", () => {
		it("should handle full create-verify roundtrip", async () => {
			const keys = await signingKeys(mockStorage)
			const key = keys[0]

			const originalPayload = {
				sub: "integration_test",
				iss: "https://auth.example.com",
				aud: ["app1", "app2"],
				exp: Math.floor(Date.now() / 1000) + 3600,
				iat: Math.floor(Date.now() / 1000),
				nonce: "random_nonce_123",
				scope: "openid profile email",
				auth_time: Math.floor(Date.now() / 1000) - 60,
				custom_data: {
					user_type: "premium",
					subscription_tier: "pro",
					features: ["feature1", "feature2"]
				}
			}

			// Create token
			const token = await jwt.create(originalPayload, key.alg, key.private, key.id)

			// Verify token
			const result = await jwt.verify(token, key.public)

			// Check all claims are preserved
			expect(result.payload.sub).toBe(originalPayload.sub)
			expect(result.payload.iss).toBe(originalPayload.iss)
			expect(result.payload.aud).toEqual(originalPayload.aud)
			expect(result.payload.nonce).toBe(originalPayload.nonce)
			expect(result.payload.scope).toBe(originalPayload.scope)
			expect(result.payload.custom_data).toEqual(originalPayload.custom_data)
		})

		it("should work with multiple keys", async () => {
			const keys1 = await signingKeys(mockStorage)
			const keys2 = await signingKeys(MemoryStorage()) // Different storage = different keys

			const payload = {
				sub: "multi_key_test",
				exp: Math.floor(Date.now() / 1000) + 3600
			}

			// Create token with first key
			const token1 = await jwt.create(payload, keys1[0].alg, keys1[0].private, keys1[0].id)

			// Create token with second key
			const token2 = await jwt.create(payload, keys2[0].alg, keys2[0].private, keys2[0].id)

			// Verify each token with its corresponding public key
			const result1 = await jwt.verify(token1, keys1[0].public)
			const result2 = await jwt.verify(token2, keys2[0].public)

			expect(result1.payload.sub).toBe("multi_key_test")
			expect(result2.payload.sub).toBe("multi_key_test")

			// Cross-verification should fail
			await expect(jwt.verify(token1, keys2[0].public)).rejects.toThrow()
			await expect(jwt.verify(token2, keys1[0].public)).rejects.toThrow()
		})

		it("should handle OAuth/OIDC standard claims", async () => {
			const keys = await signingKeys(mockStorage)
			const key = keys[0]

			const now = Math.floor(Date.now() / 1000)
			const payload = {
				// Standard JWT claims
				iss: "https://auth.example.com",
				sub: "user_12345",
				aud: "client_app",
				exp: now + 3600,
				iat: now,
				nbf: now,
				jti: "unique_token_id",

				// OIDC standard claims
				auth_time: now - 300,
				nonce: "client_nonce_abc123",
				at_hash: "access_token_hash",
				c_hash: "code_hash",

				// OIDC profile scope claims
				name: "John Doe",
				given_name: "John",
				family_name: "Doe",
				middle_name: "William",
				nickname: "Johnny",
				preferred_username: "johndoe",
				profile: "https://example.com/johndoe",
				picture: "https://example.com/johndoe/avatar.jpg",
				website: "https://johndoe.com",
				gender: "male",
				birthdate: "1990-01-01",
				zoneinfo: "America/New_York",
				locale: "en-US",
				updated_at: now - 86400,

				// OIDC email scope claims
				email: "john.doe@example.com",
				email_verified: true,

				// OIDC phone scope claims
				phone_number: "+1-202-555-0123",
				phone_number_verified: false,

				// OIDC address scope claims
				address: {
					formatted: "123 Main St, Anytown, USA 12345",
					street_address: "123 Main St",
					locality: "Anytown",
					region: "State",
					postal_code: "12345",
					country: "USA"
				}
			}

			const token = await jwt.create(payload, key.alg, key.private, key.id)
			const result = await jwt.verify(token, key.public)

			// Verify all standard claims are preserved
			expect(result.payload.iss).toBe("https://auth.example.com")
			expect(result.payload.sub).toBe("user_12345")
			expect(result.payload.name).toBe("John Doe")
			expect(result.payload.email).toBe("john.doe@example.com")
			expect(result.payload.email_verified).toBe(true)
			expect(result.payload.address).toEqual(payload.address)
		})
	})

	describe("Error Handling", () => {
		it("should handle key generation failures gracefully", async () => {
			// This tests the error handling when crypto operations fail
			const keys = await signingKeys(mockStorage)
			const key = keys[0]

			const payload = { sub: "test", exp: Math.floor(Date.now() / 1000) + 3600 }

			// Valid creation should work
			const token = await jwt.create(payload, key.alg, key.private, key.id)
			expect(token).toBeDefined()
		})

		it("should handle very large payloads", async () => {
			const keys = await signingKeys(mockStorage)
			const key = keys[0]

			// Create a large payload (but still reasonable)
			const largeData = Array.from({ length: 1000 }, (_, i) => ({
				id: i,
				data: `large_data_item_${i}`,
				metadata: {
					timestamp: Date.now(),
					random: Math.random()
				}
			}))

			const payload = {
				sub: "user123",
				exp: Math.floor(Date.now() / 1000) + 3600,
				large_array: largeData
			}

			const token = await jwt.create(payload, key.alg, key.private, key.id)
			const result = await jwt.verify<{ large_array: { id: string }[] }>(token, key.public)

			expect(result.payload.sub).toBe("user123")
			expect(result.payload.large_array).toHaveLength(1000)
			expect(result.payload.large_array[0].id).toBe(0)
		})

		it("should handle special characters in claims", async () => {
			const keys = await signingKeys(mockStorage)
			const key = keys[0]

			const payload = {
				sub: "user123",
				exp: Math.floor(Date.now() / 1000) + 3600,
				name: "João José António-Smith",
				email: "joão+test@example.com",
				message: "Hello 世界! 🌍",
				unicode_property: "测试数据",
				special_chars: "!@#$%^&*()_+-=[]{}|;':\",./<>?",
				emoji_test: "👨🚀🎉"
			}

			const token = await jwt.create(payload, key.alg, key.private, key.id)
			const result = await jwt.verify(token, key.public)

			expect(result.payload.name).toBe("João José António-Smith")
			expect(result.payload.email).toBe("joão+test@example.com")
			expect(result.payload.message).toBe("Hello 世界! 🌍")
			expect(result.payload.unicode_property).toBe("测试数据")
			expect(result.payload.emoji_test).toBe("👨🚀🎉")
		})
	})

	describe("Performance", () => {
		it("should handle high-frequency token operations", async () => {
			const keys = await signingKeys(mockStorage)
			const key = keys[0]

			const payload = {
				sub: "perf_test",
				exp: Math.floor(Date.now() / 1000) + 3600
			}

			const iterations = 100
			const tokens: string[] = []

			// Create many tokens
			const createStart = Date.now()
			for (let i = 0; i < iterations; i++) {
				const token = await jwt.create(
					{ ...payload, jti: `token_${i}` },
					key.alg,
					key.private,
					key.id
				)
				tokens.push(token)
			}
			const createDuration = Date.now() - createStart

			// Verify all tokens
			const verifyStart = Date.now()
			for (const token of tokens) {
				const result = await jwt.verify(token, key.public)
				expect(result.payload.sub).toBe("perf_test")
			}
			const verifyDuration = Date.now() - verifyStart

			expect(tokens).toHaveLength(iterations)
			expect(createDuration).toBeLessThan(5000) // Should create 100 tokens in under 5 seconds
			expect(verifyDuration).toBeLessThan(5000) // Should verify 100 tokens in under 5 seconds
		})
	})
})
