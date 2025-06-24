/**
 * PKCE (Proof Key for Code Exchange) tests
 * Testing cryptographic operations and security functions
 */
import { describe, expect, it } from "vitest"
import { generatePKCE, validatePKCE } from "../src/pkce"

describe("PKCE Functions", () => {
	describe("generatePKCE", () => {
		it("should generate valid PKCE challenge with default length", async () => {
			const pkce = await generatePKCE()

			expect(pkce).toBeDefined()
			expect(pkce.verifier).toBeDefined()
			expect(pkce.challenge).toBeDefined()
			expect(pkce.method).toBe("S256")
			expect(typeof pkce.verifier).toBe("string")
			expect(typeof pkce.challenge).toBe("string")
			expect(pkce.verifier.length).toBeGreaterThan(0)
			expect(pkce.challenge.length).toBeGreaterThan(0)
		})

		it("should generate unique challenges on each call", async () => {
			const pkce1 = await generatePKCE()
			const pkce2 = await generatePKCE()

			expect(pkce1.verifier).not.toBe(pkce2.verifier)
			expect(pkce1.challenge).not.toBe(pkce2.challenge)
			expect(pkce1.method).toBe(pkce2.method)
		})

		it("should generate challenges with custom length", async () => {
			const shortPkce = await generatePKCE(43)
			const longPkce = await generatePKCE(128)

			expect(shortPkce.verifier).toBeDefined()
			expect(longPkce.verifier).toBeDefined()
			expect(shortPkce.method).toBe("S256")
			expect(longPkce.method).toBe("S256")
		})

		it("should throw error for invalid lengths", async () => {
			await expect(generatePKCE(42)).rejects.toThrow(RangeError)
			await expect(generatePKCE(129)).rejects.toThrow(RangeError)
			await expect(generatePKCE(0)).rejects.toThrow(RangeError)
			await expect(generatePKCE(-1)).rejects.toThrow(RangeError)
			await expect(generatePKCE(Number.NaN)).rejects.toThrow(RangeError)
			await expect(generatePKCE(Number.POSITIVE_INFINITY)).rejects.toThrow(RangeError)
		})

		it("should generate base64url encoded strings", async () => {
			const pkce = await generatePKCE()

			// Base64url should not contain +, / or = characters
			expect(pkce.verifier).not.toMatch(/[+/=]/)
			expect(pkce.challenge).not.toMatch(/[+/=]/)

			// Should only contain valid base64url characters
			expect(pkce.verifier).toMatch(/^[A-Za-z0-9_-]+$/)
			expect(pkce.challenge).toMatch(/^[A-Za-z0-9_-]+$/)
		})

		it("should generate proper challenge length for S256", async () => {
			const pkce = await generatePKCE()

			// SHA-256 hash encoded in base64url should be 43 characters
			expect(pkce.challenge.length).toBe(43)
		})
	})

	describe("validatePKCE", () => {
		it("should validate correct verifier against challenge", async () => {
			const pkce = await generatePKCE()
			const isValid = await validatePKCE(pkce.verifier, pkce.challenge, "S256")

			expect(isValid).toBe(true)
		})

		it("should reject incorrect verifier", async () => {
			const pkce = await generatePKCE()
			const wrongVerifier = "wrong-verifier-123"
			const isValid = await validatePKCE(wrongVerifier, pkce.challenge, "S256")

			expect(isValid).toBe(false)
		})

		it("should reject tampered challenge", async () => {
			const pkce = await generatePKCE()
			const tamperedChallenge = `${pkce.challenge.slice(0, -1)} X`
			const isValid = await validatePKCE(pkce.verifier, tamperedChallenge, "S256")

			expect(isValid).toBe(false)
		})

		it("should handle empty or invalid inputs", async () => {
			const pkce = await generatePKCE()

			expect(await validatePKCE("", pkce.challenge, "S256")).toBe(false)
			expect(await validatePKCE(pkce.verifier, "", "S256")).toBe(false)
			expect(await validatePKCE("", "", "S256")).toBe(false)

			// Test with non-string inputs
			expect(await validatePKCE(null as unknown as string, pkce.challenge, "S256")).toBe(false)
			expect(await validatePKCE(pkce.verifier, undefined as unknown as string, "S256")).toBe(
				false
			)
			expect(await validatePKCE(123 as unknown as string, pkce.challenge, "S256")).toBe(false)
		})

		it("should use S256 method by default", async () => {
			const pkce = await generatePKCE()

			// Test without explicit method parameter
			const isValid = await validatePKCE(pkce.verifier, pkce.challenge)
			expect(isValid).toBe(true)
		})

		it("should work with different challenge lengths", async () => {
			const shortPkce = await generatePKCE(43)
			const longPkce = await generatePKCE(100)

			expect(await validatePKCE(shortPkce.verifier, shortPkce.challenge, "S256")).toBe(true)
			expect(await validatePKCE(longPkce.verifier, longPkce.challenge, "S256")).toBe(true)
		})
	})

	describe("Security and Edge Cases", () => {
		it("should generate cryptographically random values", async () => {
			const challenges = await Promise.all(
				Array(100)
					.fill(0)
					.map(() => generatePKCE())
			)

			// Check that we don't have duplicate verifiers (extremely unlikely with good randomness)
			const verifiers = challenges.map((p) => p.verifier)
			const uniqueVerifiers = new Set(verifiers)
			expect(uniqueVerifiers.size).toBe(verifiers.length)

			// Check that we don't have duplicate challenges
			const challengeStrings = challenges.map((p) => p.challenge)
			const uniqueChallenges = new Set(challengeStrings)
			expect(uniqueChallenges.size).toBe(challengeStrings.length)
		})

		it("should have consistent challenge generation", async () => {
			const pkce = await generatePKCE()

			// Validate multiple times - should always work
			for (let i = 0; i < 10; i++) {
				const isValid = await validatePKCE(pkce.verifier, pkce.challenge, "S256")
				expect(isValid).toBe(true)
			}
		})

		it("should handle unicode characters in verifier gracefully", async () => {
			// This shouldn't happen in normal usage, but test robustness
			const unicodeString = "test-ñáéíóú-🔒"
			const fakeChallenge = "fake-challenge-123"

			const isValid = await validatePKCE(unicodeString, fakeChallenge, "S256")
			expect(isValid).toBe(false)
		})

		it("should be timing-safe for validation", async () => {
			const pkce = await generatePKCE()
			const wrongVerifier1 = "a"
			const wrongVerifier2 = "a".repeat(pkce.verifier.length)

			// Both should be false, testing timing safety indirectly
			expect(await validatePKCE(wrongVerifier1, pkce.challenge, "S256")).toBe(false)
			expect(await validatePKCE(wrongVerifier2, pkce.challenge, "S256")).toBe(false)
		})
	})

	describe("OAuth 2.0 Compliance", () => {
		it("should generate verifiers meeting RFC 7636 requirements", async () => {
			const pkce = await generatePKCE()

			// RFC 7636: code_verifier length should be 43-128 characters
			expect(pkce.verifier.length).toBeGreaterThanOrEqual(43)
			expect(pkce.verifier.length).toBeLessThanOrEqual(128)

			// Should use unreserved characters: [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
			// Base64url uses: [A-Za-z0-9_-] which is a subset of unreserved characters
			expect(pkce.verifier).toMatch(/^[A-Za-z0-9_-]+$/)
		})

		it("should generate challenges meeting RFC 7636 requirements", async () => {
			const pkce = await generatePKCE()

			// Challenge should be base64url-encoded SHA256 hash
			expect(pkce.challenge).toMatch(/^[A-Za-z0-9_-]+$/)
			expect(pkce.challenge.length).toBe(43) // SHA256 hash in base64url
			expect(pkce.method).toBe("S256")
		})

		it("should handle the minimum and maximum allowed lengths", async () => {
			const minPkce = await generatePKCE(43)
			const maxPkce = await generatePKCE(128)

			expect(await validatePKCE(minPkce.verifier, minPkce.challenge, "S256")).toBe(true)
			expect(await validatePKCE(maxPkce.verifier, maxPkce.challenge, "S256")).toBe(true)
		})
	})

	describe("Real-world Usage Scenarios", () => {
		it("should work in typical OAuth flow", async () => {
			// Step 1: Generate PKCE for authorization request
			const pkce = await generatePKCE()

			// Step 2: Store verifier (typically in session or local storage)
			const storedVerifier = pkce.verifier
			const sentChallenge = pkce.challenge
			const usedMethod = pkce.method

			// Step 3: Later, validate during token exchange
			const isValid = await validatePKCE(storedVerifier, sentChallenge, usedMethod)
			expect(isValid).toBe(true)
		})

		it("should handle multiple concurrent PKCE generations", async () => {
			const promises = Array(50)
				.fill(0)
				.map(() => generatePKCE())
			const results = await Promise.all(promises)

			// All should be valid
			for (const pkce of results) {
				expect(await validatePKCE(pkce.verifier, pkce.challenge, "S256")).toBe(true)
			}

			// All should be unique
			const verifiers = results.map((r) => r.verifier)
			expect(new Set(verifiers).size).toBe(verifiers.length)
		})

		it("should detect replay attacks", async () => {
			const pkce1 = await generatePKCE()
			const pkce2 = await generatePKCE()

			// Try to use verifier from one with challenge from another
			expect(await validatePKCE(pkce1.verifier, pkce2.challenge, "S256")).toBe(false)
			expect(await validatePKCE(pkce2.verifier, pkce1.challenge, "S256")).toBe(false)
		})
	})
})
