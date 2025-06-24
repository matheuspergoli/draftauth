/**
 * OAuth 2.0 scopes utility tests
 */
import { describe, expect, it } from "vitest"
import { parseScopes, validateScopes } from "../src/scopes"

describe("Scopes Functions", () => {
	describe("parseScopes", () => {
		it("should parse space-separated scope strings", () => {
			expect(parseScopes("openid profile email")).toEqual(["openid", "profile", "email"])
			expect(parseScopes("read write")).toEqual(["read", "write"])
			expect(parseScopes("single")).toEqual(["single"])
		})

		it("should handle scope arrays", () => {
			expect(parseScopes(["openid", "profile", "email"])).toEqual([
				"openid",
				"profile",
				"email"
			])
			expect(parseScopes(["read", "write"])).toEqual(["read", "write"])
			expect(parseScopes(["single"])).toEqual(["single"])
		})

		it("should filter out empty values", () => {
			expect(parseScopes("openid  profile   email")).toEqual(["openid", "profile", "email"])
			expect(parseScopes(["openid", "", "profile", "email"])).toEqual([
				"openid",
				"profile",
				"email"
			])
			expect(parseScopes("  openid   ")).toEqual(["openid"])
		})

		it("should handle null and undefined inputs", () => {
			expect(parseScopes(null)).toEqual([])
			expect(parseScopes(undefined)).toEqual([])
		})

		it("should handle empty inputs", () => {
			expect(parseScopes("")).toEqual([])
			expect(parseScopes("   ")).toEqual([])
			expect(parseScopes([])).toEqual([])
		})

		it("should handle complex scope names", () => {
			expect(parseScopes("https://api.example.com/read user:profile repo:write")).toEqual([
				"https://api.example.com/read",
				"user:profile",
				"repo:write"
			])
		})

		it("should preserve scope order", () => {
			expect(parseScopes("email profile openid")).toEqual(["email", "profile", "openid"])
			expect(parseScopes(["email", "profile", "openid"])).toEqual([
				"email",
				"profile",
				"openid"
			])
		})

		it("should handle duplicate scopes", () => {
			expect(parseScopes("openid profile openid email profile")).toEqual([
				"openid",
				"profile",
				"openid",
				"email",
				"profile"
			])
		})
	})

	describe("validateScopes", () => {
		it("should return intersection of requested and authorized scopes", () => {
			const authorized = ["openid", "profile", "email", "offline_access"]

			expect(validateScopes("openid profile", authorized)).toEqual(["openid", "profile"])
			expect(validateScopes("email", authorized)).toEqual(["email"])
			expect(validateScopes("offline_access", authorized)).toEqual(["offline_access"])
		})

		it("should prevent scope escalation", () => {
			const authorized = ["openid", "profile"]

			expect(validateScopes("openid admin", authorized)).toEqual(["openid"])
			expect(validateScopes("admin superuser", authorized)).toEqual([])
			expect(validateScopes("openid profile email", authorized)).toEqual(["openid", "profile"])
		})

		it("should return all authorized scopes when token request is null/undefined", () => {
			const authorized = ["openid", "profile", "email"]

			expect(validateScopes(null, authorized)).toEqual(authorized)
			expect(validateScopes(undefined, authorized)).toEqual(authorized)
		})

		it("should handle empty authorized scopes", () => {
			expect(validateScopes("openid profile", [])).toEqual([])
			expect(validateScopes("openid profile", undefined)).toBeUndefined()
		})

		it("should handle empty token request", () => {
			const authorized = ["openid", "profile", "email"]

			expect(validateScopes("", authorized)).toEqual([])
			expect(validateScopes("   ", authorized)).toEqual([])
		})

		it("should maintain order based on token request", () => {
			const authorized = ["openid", "profile", "email", "offline_access"]

			expect(validateScopes("email openid profile", authorized)).toEqual([
				"email",
				"openid",
				"profile"
			])
			expect(validateScopes("offline_access email", authorized)).toEqual([
				"offline_access",
				"email"
			])
		})

		it("should handle complex scope validation scenarios", () => {
			const authorized = [
				"https://api.example.com/read",
				"user:profile",
				"repo:write",
				"openid"
			]

			expect(validateScopes("user:profile repo:write", authorized)).toEqual([
				"user:profile",
				"repo:write"
			])

			expect(validateScopes("https://api.example.com/read openid", authorized)).toEqual([
				"https://api.example.com/read",
				"openid"
			])
		})

		it("should handle duplicate scopes in validation", () => {
			const authorized = ["openid", "profile", "email"]

			expect(validateScopes("openid profile openid", authorized)).toEqual([
				"openid",
				"profile"
			])
		})

		it("should be case sensitive", () => {
			const authorized = ["openid", "profile", "email"]

			expect(validateScopes("OpenID Profile", authorized)).toEqual([])
			expect(validateScopes("openid PROFILE", authorized)).toEqual(["openid"])
		})
	})

	describe("Integration Scenarios", () => {
		it("should work together in OAuth flow", () => {
			// Authorization request
			const authRequestScopes = "openid profile email offline_access"
			const parsedAuthScopes = parseScopes(authRequestScopes)
			expect(parsedAuthScopes).toEqual(["openid", "profile", "email", "offline_access"])

			// Token request with subset of scopes
			const tokenRequestScopes = "openid email"
			const validatedScopes = validateScopes(tokenRequestScopes, parsedAuthScopes)
			expect(validatedScopes).toEqual(["openid", "email"])
		})

		it("should handle refresh token scenario", () => {
			const originalScopes = ["openid", "profile", "email", "offline_access"]

			// Refresh token can request same or fewer scopes
			expect(validateScopes("openid profile", originalScopes)).toEqual(["openid", "profile"])
			expect(validateScopes(null, originalScopes)).toEqual(originalScopes)

			// Cannot escalate scopes during refresh
			expect(validateScopes("openid profile admin", originalScopes)).toEqual([
				"openid",
				"profile"
			])
		})

		it("should handle OIDC standard scopes", () => {
			const oidcScopes = ["openid", "profile", "email", "address", "phone"]

			expect(validateScopes("openid profile email", oidcScopes)).toEqual([
				"openid",
				"profile",
				"email"
			])

			expect(validateScopes("openid address phone", oidcScopes)).toEqual([
				"openid",
				"address",
				"phone"
			])
		})

		it("should handle custom API scopes", () => {
			const apiScopes = ["api:read", "api:write", "api:delete", "user:profile", "admin:users"]

			expect(validateScopes("api:read api:write user:profile", apiScopes)).toEqual([
				"api:read",
				"api:write",
				"user:profile"
			])

			// Prevent escalation to admin scope
			expect(validateScopes("api:read admin:users", apiScopes)).toEqual([
				"api:read",
				"admin:users"
			])
		})

		it("should handle URL-based scopes", () => {
			const urlScopes = [
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
				"https://www.googleapis.com/auth/calendar.readonly"
			]

			const requested =
				"https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/calendar.readonly"

			expect(validateScopes(requested, urlScopes)).toEqual([
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/calendar.readonly"
			])
		})
	})

	describe("Edge Cases", () => {
		it("should handle very long scope strings", () => {
			const longScope = "a".repeat(1000)
			const longScopeString = `openid ${longScope} profile`

			expect(parseScopes(longScopeString)).toEqual(["openid", longScope, "profile"])
		})

		it("should handle special characters in scopes", () => {
			const specialScopes = [
				"scope:with:colons",
				"scope-with-dashes",
				"scope_with_underscores"
			]

			expect(
				parseScopes("scope:with:colons scope-with-dashes scope_with_underscores")
			).toEqual(specialScopes)
			expect(validateScopes("scope:with:colons scope-with-dashes", specialScopes)).toEqual([
				"scope:with:colons",
				"scope-with-dashes"
			])
		})

		it("should handle Unicode characters in scopes", () => {
			const unicodeScopes = ["読み取り", "書き込み", "管理者"]

			expect(parseScopes(["読み取り", "書き込み", "管理者"])).toEqual(unicodeScopes)
			expect(validateScopes("読み取り 書き込み", unicodeScopes)).toEqual([
				"読み取り",
				"書き込み"
			])
		})

		it("should handle numeric scopes", () => {
			const numericScopes = ["scope1", "scope2", "scope123"]

			expect(parseScopes("scope1 scope2 scope123")).toEqual(numericScopes)
			expect(validateScopes("scope1 scope123", numericScopes)).toEqual(["scope1", "scope123"])
		})

		it("should handle mixed input types", () => {
			// Test parseScopes with different falsy values in array
			// These falsy values should be filtered out by the filter(Boolean) call
			const mixedArray = ["valid", false, "scope", 0, "test"] as (string | boolean | number)[]
			expect(parseScopes(mixedArray as string[])).toEqual(["valid", "scope", "test"])
		})
	})

	describe("Performance", () => {
		it("should handle large scope lists efficiently", () => {
			const largeAuthorizedList = Array.from({ length: 1000 }, (_, i) => `scope${i}`)
			const requestedScopes = "scope1 scope100 scope500 scope999"

			const start = Date.now()
			const result = validateScopes(requestedScopes, largeAuthorizedList)
			const duration = Date.now() - start

			expect(result).toEqual(["scope1", "scope100", "scope500", "scope999"])
			expect(duration).toBeLessThan(50) // Should be fast
		})

		it("should parse large scope strings efficiently", () => {
			const largeScopes = Array.from({ length: 100 }, (_, i) => `scope${i}`).join(" ")

			const start = Date.now()
			const result = parseScopes(largeScopes)
			const duration = Date.now() - start

			expect(result).toHaveLength(100)
			expect(duration).toBeLessThan(50) // Should be fast
		})
	})
})
