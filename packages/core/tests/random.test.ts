/**
 * Random utilities tests
 * Testing cryptographic random generation and timing-safe comparison
 */
import { describe, expect, it } from "vitest"
import { generateUnbiasedDigits, timingSafeCompare } from "../src/random"

describe("Random Utilities", () => {
	describe("generateUnbiasedDigits", () => {
		it("should generate digits of specified length", () => {
			const result1 = generateUnbiasedDigits(1)
			const result6 = generateUnbiasedDigits(6)
			const result10 = generateUnbiasedDigits(10)

			expect(result1).toHaveLength(1)
			expect(result6).toHaveLength(6)
			expect(result10).toHaveLength(10)
		})

		it("should generate only numeric digits", () => {
			const result = generateUnbiasedDigits(100)
			expect(result).toMatch(/^[0-9]+$/)
		})

		it("should generate different results on each call", () => {
			const results = Array(50)
				.fill(0)
				.map(() => generateUnbiasedDigits(10))
			const uniqueResults = new Set(results)

			// With good randomness, we should get mostly unique results
			// Allow some duplicates due to randomness, but expect mostly unique
			expect(uniqueResults.size).toBeGreaterThan(40)
		})

		it("should include all digits 0-9 in large samples", () => {
			const result = generateUnbiasedDigits(1000)
			const digitCounts = new Array(10).fill(0)

			for (const char of result) {
				digitCounts[Number.parseInt(char)]++
			}

			// All digits should appear at least once in 1000 digits
			for (let i = 0; i < 10; i++) {
				expect(digitCounts[i]).toBeGreaterThan(0)
			}
		})

		it("should have roughly uniform distribution", () => {
			const result = generateUnbiasedDigits(10000)
			const digitCounts = new Array(10).fill(0)

			for (const char of result) {
				digitCounts[Number.parseInt(char)]++
			}

			// Each digit should appear roughly 1000 times (±200 for randomness)
			for (let i = 0; i < 10; i++) {
				expect(digitCounts[i]).toBeGreaterThan(800)
				expect(digitCounts[i]).toBeLessThan(1200)
			}
		})

		it("should handle edge cases for length", () => {
			const single = generateUnbiasedDigits(1)
			expect(single).toHaveLength(1)
			expect(single).toMatch(/^[0-9]$/)
		})

		it("should throw error for invalid lengths", () => {
			expect(() => generateUnbiasedDigits(0)).toThrow(RangeError)
			expect(() => generateUnbiasedDigits(-1)).toThrow(RangeError)
			expect(() => generateUnbiasedDigits(-10)).toThrow(RangeError)
			expect(() => generateUnbiasedDigits(1.5)).toThrow(RangeError)
			expect(() => generateUnbiasedDigits(Number.NaN)).toThrow(RangeError)
			expect(() => generateUnbiasedDigits(Number.POSITIVE_INFINITY)).toThrow(RangeError)
		})

		it("should handle large lengths efficiently", () => {
			const start = Date.now()
			const result = generateUnbiasedDigits(10000)
			const end = Date.now()

			expect(result).toHaveLength(10000)
			expect(result).toMatch(/^[0-9]+$/)

			// Should complete in reasonable time (less than 1 second)
			expect(end - start).toBeLessThan(1000)
		})

		it("should handle maximum safe buffer size", () => {
			// Test with maximum crypto.getRandomValues buffer size (65536 bytes)
			const result = generateUnbiasedDigits(32768) // Half of max buffer to be safe
			expect(result).toHaveLength(32768)
			expect(result).toMatch(/^[0-9]+$/)
		})
	})

	describe("timingSafeCompare", () => {
		it("should return true for identical strings", () => {
			expect(timingSafeCompare("test", "test")).toBe(true)
			expect(timingSafeCompare("", "")).toBe(true)
			expect(timingSafeCompare("a", "a")).toBe(true)
			expect(timingSafeCompare("long test string", "long test string")).toBe(true)
		})

		it("should return false for different strings", () => {
			expect(timingSafeCompare("test", "Test")).toBe(false)
			expect(timingSafeCompare("test", "test2")).toBe(false)
			expect(timingSafeCompare("abc", "def")).toBe(false)
			expect(timingSafeCompare("", "test")).toBe(false)
			expect(timingSafeCompare("test", "")).toBe(false)
		})

		it("should return false for different lengths", () => {
			expect(timingSafeCompare("short", "muchLongerString")).toBe(false)
			expect(timingSafeCompare("long", "a")).toBe(false)
			expect(timingSafeCompare("test", "test1")).toBe(false)
		})

		it("should handle non-string inputs", () => {
			// Test with number types
			expect(timingSafeCompare("test", 123 as unknown as string)).toBe(false)
			expect(timingSafeCompare(123 as unknown as string, "test")).toBe(false)
			expect(timingSafeCompare(123 as unknown as string, 123 as unknown as string)).toBe(false)

			// Test with null/undefined
			expect(timingSafeCompare("test", null as unknown as string)).toBe(false)
			expect(timingSafeCompare("test", undefined as unknown as string)).toBe(false)

			// Test with object types
			expect(timingSafeCompare({} as unknown as string, "test")).toBe(false)
			expect(timingSafeCompare("test", [] as unknown as string)).toBe(false)
		})

		it("should handle unicode characters", () => {
			const unicode1 = "test-ñáéíóú-🔒"
			const unicode2 = "test-ñáéíóú-🔒"
			const unicode3 = "test-ñáéíóú-🔑"

			expect(timingSafeCompare(unicode1, unicode2)).toBe(true)
			expect(timingSafeCompare(unicode1, unicode3)).toBe(false)
		})

		it("should handle special characters", () => {
			const special1 = "test!@#$%^&*()_+-=[]{}|;:,.<>?"
			const special2 = "test!@#$%^&*()_+-=[]{}|;:,.<>?"
			const special3 = "test!@#$%^&*()_+-=[]{}|;:,.<>!"

			expect(timingSafeCompare(special1, special2)).toBe(true)
			expect(timingSafeCompare(special1, special3)).toBe(false)
		})

		it("should be consistent across multiple calls", () => {
			const str1 = "consistent-test-string"
			const str2 = "consistent-test-string"
			const str3 = "different-test-string"

			// Same comparison should always return same result
			for (let i = 0; i < 100; i++) {
				expect(timingSafeCompare(str1, str2)).toBe(true)
				expect(timingSafeCompare(str1, str3)).toBe(false)
			}
		})
	})

	describe("Security Properties", () => {
		it("generateUnbiasedDigits should avoid modulo bias", () => {
			// Test that digits are truly unbiased by generating many samples
			const samples = Array(1000)
				.fill(0)
				.map(() => generateUnbiasedDigits(1))
			const counts = new Array(10).fill(0)

			for (const sample of samples) {
				counts[Number.parseInt(sample)]++
			}

			// Each digit should appear roughly 100 times (±30 for randomness)
			for (let i = 0; i < 10; i++) {
				expect(counts[i]).toBeGreaterThan(70)
				expect(counts[i]).toBeLessThan(130)
			}
		})

		it("timingSafeCompare should handle timing attack scenarios", () => {
			const correctToken = "secret-token-12345678"
			const wrongTokens = [
				"a", // Very short
				"secret-token-12345677", // Different at end
				"xecret-token-12345678", // Different at start
				"secret-xoken-12345678", // Different in middle
				"SECRET-TOKEN-12345678", // Case difference
				"" // Empty string
			]

			// All wrong tokens should return false
			for (const wrongToken of wrongTokens) {
				expect(timingSafeCompare(correctToken, wrongToken)).toBe(false)
			}

			// Correct token should return true
			expect(timingSafeCompare(correctToken, correctToken)).toBe(true)
		})
	})

	describe("Real-world Usage Scenarios", () => {
		it("should generate PIN codes", () => {
			const pin = generateUnbiasedDigits(4)
			expect(pin).toMatch(/^[0-9]{4}$/)
		})

		it("should generate verification codes", () => {
			const code = generateUnbiasedDigits(6)
			expect(code).toMatch(/^[0-9]{6}$/)
		})

		it("should generate OTP codes", () => {
			const otp = generateUnbiasedDigits(8)
			expect(otp).toMatch(/^[0-9]{8}$/)
		})

		it("should compare authentication tokens safely", () => {
			const realToken = "auth-token-abcd1234"
			const userToken = "auth-token-abcd1234"
			const fakeToken = "auth-token-abcd1235"

			expect(timingSafeCompare(realToken, userToken)).toBe(true)
			expect(timingSafeCompare(realToken, fakeToken)).toBe(false)
		})

		it("should compare session IDs safely", () => {
			const sessionId = "sess_1234567890abcdef"
			const validSession = "sess_1234567890abcdef"
			const invalidSession = "sess_1234567890abcdeg"

			expect(timingSafeCompare(sessionId, validSession)).toBe(true)
			expect(timingSafeCompare(sessionId, invalidSession)).toBe(false)
		})

		it("should handle concurrent random generation", async () => {
			const promises = Array(100)
				.fill(0)
				.map(() => Promise.resolve(generateUnbiasedDigits(10)))

			const results = await Promise.all(promises)

			// All results should be valid
			for (const result of results) {
				expect(result).toMatch(/^[0-9]{10}$/)
			}

			// Most should be unique
			const uniqueResults = new Set(results)
			expect(uniqueResults.size).toBeGreaterThan(90)
		})
	})

	describe("Performance and Efficiency", () => {
		it("should generate digits efficiently", () => {
			const start = Date.now()

			// Generate many short codes
			for (let i = 0; i < 1000; i++) {
				generateUnbiasedDigits(6)
			}

			const end = Date.now()
			expect(end - start).toBeLessThan(1000) // Should be very fast
		})

		it("should compare strings efficiently", () => {
			const str1 = "test-string-for-performance-testing"
			const str2 = "test-string-for-performance-testing"
			const str3 = "different-string-for-performance-test"

			const start = Date.now()

			// Perform many comparisons
			for (let i = 0; i < 10000; i++) {
				timingSafeCompare(str1, str2)
				timingSafeCompare(str1, str3)
			}

			const end = Date.now()
			expect(end - start).toBeLessThan(1000) // Should be fast
		})
	})
})
