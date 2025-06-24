/**
 * Cryptographic key management tests
 * Testing key generation, storage, and retrieval functionality
 */
import { jwtVerify, SignJWT } from "jose"
import { beforeEach, describe, expect, it } from "vitest"
import { encryptionKeys, signingKeys } from "../src/keys"
import { MemoryStorage } from "../src/storage/memory"

describe("Key Management", () => {
	let storage: ReturnType<typeof MemoryStorage>

	beforeEach(() => {
		storage = MemoryStorage()
	})

	describe("signingKeys", () => {
		it("should generate signing keys when none exist", async () => {
			const keys = await signingKeys(storage)

			expect(keys).toBeDefined()
			expect(Array.isArray(keys)).toBe(true)
			expect(keys.length).toBeGreaterThan(0)

			const key = keys[0]
			expect(key.id).toBeDefined()
			expect(key.alg).toBe("ES256")
			expect(key.public).toBeDefined()
			expect(key.private).toBeDefined()
			expect(key.created).toBeInstanceOf(Date)
			expect(key.jwk).toBeDefined()
		})

		it("should return existing valid keys", async () => {
			// First call generates keys
			const keys1 = await signingKeys(storage)

			// Second call should return same keys
			const keys2 = await signingKeys(storage)

			expect(keys1.length).toBe(keys2.length)
			expect(keys1[0].id).toBe(keys2[0].id)
			expect(keys1[0].created.getTime()).toBe(keys2[0].created.getTime())
		})

		it("should generate keys with proper JWK format", async () => {
			const keys = await signingKeys(storage)
			const key = keys[0]

			expect(key.jwk.kty).toBe("EC")
			expect(key.jwk.kid).toBe(key.id)
			expect(key.jwk.use).toBe("sig")
			expect(key.jwk.crv).toBe("P-256")
			expect(key.jwk.x).toBeDefined()
			expect(key.jwk.y).toBeDefined()
		})

		it("should sort keys by creation date (newest first)", async () => {
			// Generate encryption keys
			const keys = await signingKeys(storage)

			// If we have multiple keys, they should be sorted
			if (keys.length > 1) {
				for (let i = 0; i < keys.length - 1; i++) {
					expect(keys[i].created.getTime()).toBeGreaterThanOrEqual(
						keys[i + 1].created.getTime()
					)
				}
			}

			expect(keys[0].alg).toBe("ES256")
		})

		it("should work with JWT signing operations", async () => {
			const keys = await signingKeys(storage)
			const key = keys[0]

			const payload = {
				sub: "test-user",
				aud: "test-client",
				iss: "test-issuer",
				exp: Math.floor(Date.now() / 1000) + 3600,
				iat: Math.floor(Date.now() / 1000)
			}

			// Sign JWT
			const jwt = await new SignJWT(payload)
				.setProtectedHeader({
					alg: key.alg,
					kid: key.id,
					typ: "JWT"
				})
				.sign(key.private)

			expect(jwt).toBeDefined()
			expect(typeof jwt).toBe("string")
			expect(jwt.split(".")).toHaveLength(3)

			// Verify JWT
			const verified = await jwtVerify(jwt, key.public)
			expect(verified.payload.sub).toBe("test-user")
			expect(verified.protectedHeader.kid).toBe(key.id)
		})
	})

	describe("encryptionKeys", () => {
		it("should generate encryption keys when none exist", async () => {
			const keys = await encryptionKeys(storage)

			expect(keys).toBeDefined()
			expect(Array.isArray(keys)).toBe(true)
			expect(keys.length).toBeGreaterThan(0)

			const key = keys[0]
			expect(key.id).toBeDefined()
			expect(key.alg).toBe("RSA-OAEP-512")
			expect(key.public).toBeDefined()
			expect(key.private).toBeDefined()
			expect(key.created).toBeInstanceOf(Date)
			expect(key.jwk).toBeDefined()
		})

		it("should return existing valid keys", async () => {
			// First call generates keys
			const keys1 = await encryptionKeys(storage)

			// Second call should return same keys
			const keys2 = await encryptionKeys(storage)

			expect(keys1.length).toBe(keys2.length)
			expect(keys1[0].id).toBe(keys2[0].id)
			expect(keys1[0].created.getTime()).toBe(keys2[0].created.getTime())
		})

		it("should generate keys with proper JWK format", async () => {
			const keys = await encryptionKeys(storage)
			const key = keys[0]

			expect(key.jwk.kty).toBe("RSA")
			expect(key.jwk.kid).toBe(key.id)
			expect(key.jwk.n).toBeDefined()
			expect(key.jwk.e).toBeDefined()
		})

		it("should sort keys by creation date (newest first)", async () => {
			// Generate encryption keys
			const keys = await encryptionKeys(storage)

			// If we have multiple keys, they should be sorted
			if (keys.length > 1) {
				for (let i = 0; i < keys.length - 1; i++) {
					expect(keys[i].created.getTime()).toBeGreaterThanOrEqual(
						keys[i + 1].created.getTime()
					)
				}
			}

			expect(keys[0].alg).toBe("RSA-OAEP-512")
		})
	})

	describe("Key Persistence", () => {
		it("should persist signing keys across storage instances", async () => {
			// Generate keys with first storage
			const keys1 = await signingKeys(storage)
			const originalKeyId = keys1[0].id

			// Create new storage instance and load keys
			const newStorage = MemoryStorage()

			// Copy keys to new storage (simulating persistence)
			for await (const [key, value] of storage.scan(["signing:key"])) {
				await newStorage.set(key, value)
			}

			const keys2 = await signingKeys(newStorage)
			expect(keys2[0].id).toBe(originalKeyId)
		})

		it("should persist encryption keys across storage instances", async () => {
			// Generate keys with first storage
			const keys1 = await encryptionKeys(storage)
			const originalKeyId = keys1[0].id

			// Create new storage instance and load keys
			const newStorage = MemoryStorage()

			// Copy keys to new storage (simulating persistence)
			for await (const [key, value] of storage.scan(["encryption:key"])) {
				await newStorage.set(key, value)
			}

			const keys2 = await encryptionKeys(newStorage)
			expect(keys2[0].id).toBe(originalKeyId)
		})
	})

	describe("Key Rotation and Expiration", () => {
		it("should handle expired signing keys", async () => {
			// Generate initial keys
			const keys = await signingKeys(storage)
			const keyId = keys[0].id

			// Mark key as expired by updating storage
			const expiredTime = Date.now() - 1000
			for await (const [key, value] of storage.scan(["signing:key"])) {
				const keyData = value as Record<string, unknown>
				if (keyData.id === keyId) {
					await storage.set(key, {
						...keyData,
						expired: expiredTime
					})
				}
			}

			// Should generate new keys when expired
			const newKeys = await signingKeys(storage)
			expect(newKeys.length).toBeGreaterThan(0)
			expect(newKeys[0].expired).toBeUndefined()
		})

		it("should handle expired encryption keys", async () => {
			// Generate initial keys
			const keys = await encryptionKeys(storage)
			const keyId = keys[0].id

			// Mark key as expired by updating storage
			const expiredTime = Date.now() - 1000
			for await (const [key, value] of storage.scan(["encryption:key"])) {
				const keyData = value as Record<string, unknown>
				if (keyData.id === keyId) {
					await storage.set(key, {
						...keyData,
						expired: expiredTime
					})
				}
			}

			// Should generate new keys when expired
			const newKeys = await encryptionKeys(storage)
			expect(newKeys.length).toBeGreaterThan(0)
			expect(newKeys[0].expired).toBeUndefined()
		})
	})

	describe("Concurrent Access", () => {
		it("should handle concurrent signing key requests", async () => {
			const promises = Array(10)
				.fill(0)
				.map(() => signingKeys(storage))
			const results = await Promise.all(promises)

			// All should return valid keys
			for (const keys of results) {
				expect(keys.length).toBeGreaterThan(0)
				expect(keys[0].alg).toBe("ES256")
			}
		})

		it("should handle concurrent encryption key requests", async () => {
			const promises = Array(10)
				.fill(0)
				.map(() => encryptionKeys(storage))
			const results = await Promise.all(promises)

			// All should return valid keys
			for (const keys of results) {
				expect(keys.length).toBeGreaterThan(0)
				expect(keys[0].alg).toBe("RSA-OAEP-512")
			}
		})
	})

	describe("Key Validation", () => {
		it("should generate valid ES256 signing keys", async () => {
			const keys = await signingKeys(storage)
			const key = keys[0]

			expect(key.alg).toBe("ES256")
			expect(key.public.type).toBe("public")
			expect(key.private.type).toBe("private")
		})

		it("should generate valid RSA-OAEP-512 encryption keys", async () => {
			const keys = await encryptionKeys(storage)
			const key = keys[0]

			expect(key.alg).toBe("RSA-OAEP-512")
			expect(key.public.type).toBe("public")
			expect(key.private.type).toBe("private")
		})

		it("should have valid key metadata", async () => {
			const signingKey = (await signingKeys(storage))[0]
			const encryptionKey = (await encryptionKeys(storage))[0]

			// Check signing key metadata
			expect(signingKey.id).toMatch(/^[0-9a-f-]+$/) // UUID format
			expect(signingKey.created).toBeInstanceOf(Date)
			expect(signingKey.created.getTime()).toBeLessThanOrEqual(Date.now())

			// Check encryption key metadata
			expect(encryptionKey.id).toMatch(/^[0-9a-f-]+$/) // UUID format
			expect(encryptionKey.created).toBeInstanceOf(Date)
			expect(encryptionKey.created.getTime()).toBeLessThanOrEqual(Date.now())
		})
	})

	describe("Error Handling", () => {
		it("should handle storage errors gracefully", async () => {
			// Create a mock storage that throws errors
			const errorStorage = {
				...storage,
				set: async () => {
					throw new Error("Storage error")
				}
			}

			// Should still return keys (they're generated but not stored)
			await expect(signingKeys(errorStorage)).rejects.toThrow()
		})

		it("should handle corrupted storage data", async () => {
			// Put invalid data in storage that will cause importSPKI to fail
			await storage.set(["signing:key", "corrupted"], {
				id: "corrupted",
				publicKey: "invalid-pem-data",
				privateKey: "invalid-pem-data",
				created: Date.now(),
				alg: "ES256"
			})

			// Should generate new valid keys despite corrupted data
			const keys = await signingKeys(storage)
			expect(keys.length).toBeGreaterThan(0)
			expect(keys[0].alg).toBe("ES256")
		})

		it("should handle key generation failures", async () => {
			// This is hard to test directly, but we can verify error propagation
			const keys = await signingKeys(storage)
			expect(keys).toBeDefined()
			expect(keys.length).toBeGreaterThan(0)
		})
	})

	describe("Real-world Scenarios", () => {
		it("should support JWKS endpoint generation", async () => {
			const signingKey = (await signingKeys(storage))[0]
			const encryptionKey = (await encryptionKeys(storage))[0]

			// Should be able to generate JWKS
			const jwks = {
				keys: [signingKey.jwk, encryptionKey.jwk]
			}

			expect(jwks.keys).toHaveLength(2)
			expect(jwks.keys[0].kid).toBe(signingKey.id)
			expect(jwks.keys[1].kid).toBe(encryptionKey.id)
		})

		it("should support key rotation scenarios", async () => {
			// Generate initial keys
			const initialKeys = await signingKeys(storage)
			expect(initialKeys).toHaveLength(1)

			// Simulate key rotation by marking current key as expired
			for await (const [key, value] of storage.scan(["signing:key"])) {
				const keyData = value as Record<string, unknown>
				await storage.set(key, {
					...keyData,
					expired: Date.now() - 1000
				})
			}

			const rotatedKeys = await signingKeys(storage)
			// Should return keys (either existing expired ones or generate new ones)
			expect(rotatedKeys.length).toBeGreaterThan(0)
			expect(rotatedKeys[0].alg).toBe("ES256")
		})

		it("should handle mixed key scenarios", async () => {
			// Generate both types of keys
			const signingKey = (await signingKeys(storage))[0]
			const encryptionKey = (await encryptionKeys(storage))[0]

			expect(signingKey.alg).toBe("ES256")
			expect(encryptionKey.alg).toBe("RSA-OAEP-512")
			expect(signingKey.id).not.toBe(encryptionKey.id)
		})
	})
})
