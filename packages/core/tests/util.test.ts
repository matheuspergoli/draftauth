import type { Context } from "hono"
/**
 * Utility functions tests
 */
import { describe, expect, it, vi } from "vitest"
import { getRelativeUrl, isDomainMatch, lazy } from "../src/util"

// Helper function for creating mock Hono context
const createMockContext = (url: string, headers: Record<string, string> = {}): Context =>
	({
		req: {
			url,
			header: (name: string) => headers[name]
		}
	}) as Context

describe("Utility Functions", () => {
	describe("getRelativeUrl", () => {
		it("should construct relative URL without proxy headers", () => {
			const ctx = createMockContext("https://example.com/auth")
			const result = getRelativeUrl(ctx, "./callback")

			expect(result).toBe("https://example.com/callback")
		})

		it("should handle absolute paths", () => {
			const ctx = createMockContext("https://example.com/auth/login")
			const result = getRelativeUrl(ctx, "/oauth/callback")

			expect(result).toBe("https://example.com/oauth/callback")
		})

		it("should handle x-forwarded-host header", () => {
			const ctx = createMockContext("http://localhost:3000/auth", {
				"x-forwarded-host": "myapp.com"
			})
			const result = getRelativeUrl(ctx, "./callback")

			// Port is preserved from original URL when only host is forwarded
			expect(result).toBe("http://myapp.com:3000/callback")
		})

		it("should handle x-forwarded-proto header", () => {
			const ctx = createMockContext("http://example.com/auth", {
				"x-forwarded-proto": "https"
			})
			const result = getRelativeUrl(ctx, "./callback")

			expect(result).toBe("https://example.com/callback")
		})

		it("should handle x-forwarded-port header", () => {
			const ctx = createMockContext("https://example.com/auth", {
				"x-forwarded-port": "8443"
			})
			const result = getRelativeUrl(ctx, "./callback")

			expect(result).toBe("https://example.com:8443/callback")
		})

		it("should handle all proxy headers together", () => {
			const ctx = createMockContext("http://localhost:3000/auth", {
				"x-forwarded-host": "secure-app.com",
				"x-forwarded-proto": "https",
				"x-forwarded-port": "443"
			})
			const result = getRelativeUrl(ctx, "./callback")

			// Default port 443 for HTTPS is not shown in URL
			expect(result).toBe("https://secure-app.com/callback")
		})

		it("should preserve query parameters in relative path", () => {
			const ctx = createMockContext("https://example.com/auth")
			const result = getRelativeUrl(ctx, "./callback?code=123&state=abc")

			expect(result).toBe("https://example.com/callback?code=123&state=abc")
		})

		it("should handle complex relative paths", () => {
			const ctx = createMockContext("https://example.com/api/v1/auth/login")
			const result = getRelativeUrl(ctx, "../../oauth/callback")

			expect(result).toBe("https://example.com/api/oauth/callback")
		})

		it("should handle paths with fragments", () => {
			const ctx = createMockContext("https://example.com/auth")
			const result = getRelativeUrl(ctx, "./callback#section")

			expect(result).toBe("https://example.com/callback#section")
		})

		it("should handle load balancer scenarios", () => {
			// Simulating traffic going through multiple proxies
			const ctx = createMockContext("http://internal-service:8080/auth", {
				"x-forwarded-host": "api.company.com",
				"x-forwarded-proto": "https",
				"x-forwarded-port": "443"
			})
			const result = getRelativeUrl(ctx, "./callback")

			// Default port 443 for HTTPS is not shown in URL
			expect(result).toBe("https://api.company.com/callback")
		})

		it("should handle containerized environments", () => {
			const ctx = createMockContext("http://app-container:3000/auth", {
				"x-forwarded-host": "myapp.herokuapp.com",
				"x-forwarded-proto": "https"
			})
			const result = getRelativeUrl(ctx, "../admin/users")

			// Port is preserved from original URL when not explicitly forwarded
			expect(result).toBe("https://myapp.herokuapp.com:3000/admin/users")
		})

		it("should preserve existing port when no forwarded port", () => {
			const ctx = createMockContext("https://example.com:8443/auth", {
				"x-forwarded-host": "proxy.example.com"
			})
			const result = getRelativeUrl(ctx, "./callback")

			expect(result).toBe("https://proxy.example.com:8443/callback")
		})

		it("should handle edge case with empty path", () => {
			const ctx = createMockContext("https://example.com/auth")
			const result = getRelativeUrl(ctx, "")

			expect(result).toBe("https://example.com/auth")
		})

		it("should handle special characters in URLs", () => {
			const ctx = createMockContext("https://example.com/auth")
			const result = getRelativeUrl(ctx, "./callback?redirect_uri=https%3A//app.com/home")

			expect(result).toBe("https://example.com/callback?redirect_uri=https%3A//app.com/home")
		})
	})

	describe("isDomainMatch", () => {
		describe("Basic Domain Matching", () => {
			it("should match identical domains", () => {
				expect(isDomainMatch("example.com", "example.com")).toBe(true)
				expect(isDomainMatch("api.example.com", "api.example.com")).toBe(true)
				expect(isDomainMatch("sub.domain.example.com", "sub.domain.example.com")).toBe(true)
			})

			it("should match subdomains of same domain", () => {
				expect(isDomainMatch("app.example.com", "auth.example.com")).toBe(true)
				expect(isDomainMatch("api.service.com", "web.service.com")).toBe(true)
				expect(isDomainMatch("example.com", "www.example.com")).toBe(true)
			})

			it("should not match different domains", () => {
				expect(isDomainMatch("example.com", "evil.com")).toBe(false)
				expect(isDomainMatch("app.example.com", "app.malicious.com")).toBe(false)
				expect(isDomainMatch("safe.org", "dangerous.net")).toBe(false)
			})

			it("should handle single-level domains", () => {
				expect(isDomainMatch("localhost", "localhost")).toBe(true)
				expect(isDomainMatch("localhost", "127.0.0.1")).toBe(false)
			})
		})

		describe("Two-Part TLD Handling", () => {
			it("should correctly handle co.uk domains", () => {
				expect(isDomainMatch("example.co.uk", "sub.example.co.uk")).toBe(true)
				expect(isDomainMatch("app.company.co.uk", "auth.company.co.uk")).toBe(true)
				expect(isDomainMatch("different.co.uk", "example.co.uk")).toBe(false)
			})

			it("should correctly handle com.br domains", () => {
				expect(isDomainMatch("empresa.com.br", "api.empresa.com.br")).toBe(true)
				expect(isDomainMatch("site.com.br", "outraempresa.com.br")).toBe(false)
			})

			it("should correctly handle co.jp domains", () => {
				expect(isDomainMatch("company.co.jp", "subdomain.company.co.jp")).toBe(true)
				expect(isDomainMatch("different.co.jp", "company.co.jp")).toBe(false)
			})

			it("should correctly handle com.au domains", () => {
				expect(isDomainMatch("business.com.au", "app.business.com.au")).toBe(true)
				expect(isDomainMatch("site1.com.au", "site2.com.au")).toBe(false)
			})

			it("should handle all supported two-part TLDs", () => {
				const twoPartTlds = [
					"co.uk",
					"co.jp",
					"co.kr",
					"co.nz",
					"co.za",
					"co.in",
					"com.au",
					"com.br",
					"com.cn",
					"com.mx",
					"com.tw",
					"net.au",
					"org.uk",
					"ne.jp",
					"ac.uk",
					"gov.uk",
					"edu.au",
					"gov.au"
				]

				for (const tld of twoPartTlds) {
					expect(isDomainMatch(`example.${tld}`, `sub.example.${tld}`)).toBe(true)
					expect(isDomainMatch(`different.${tld}`, `example.${tld}`)).toBe(false)
				}
			})
		})

		describe("Complex Domain Scenarios", () => {
			it("should handle deeply nested subdomains", () => {
				expect(isDomainMatch("a.b.c.d.example.com", "x.y.z.example.com")).toBe(true)

				expect(
					isDomainMatch(
						"very.deep.nested.subdomain.company.co.uk",
						"another.deep.nested.subdomain.company.co.uk"
					)
				).toBe(true)
			})

			it("should distinguish between similar domains", () => {
				expect(isDomainMatch("example.com", "fakeexample.com")).toBe(false)
				expect(isDomainMatch("app-example.com", "app.example.com")).toBe(false)
				expect(isDomainMatch("example.org", "example.com")).toBe(false)
			})

			it("should handle edge cases with short domains", () => {
				// For very short domains, the function compares the last 2 parts
				// "a.b" vs "c.b" - last 2 parts are "a.b" vs "c.b" (different)
				expect(isDomainMatch("a.b", "c.b")).toBe(false)
				expect(isDomainMatch("x.y", "x.z")).toBe(false)
				// These should match because they're identical
				expect(isDomainMatch("same.domain", "same.domain")).toBe(true)
			})

			it("should handle mixed case domains", () => {
				// The function is case-sensitive - doesn't convert to lowercase
				expect(isDomainMatch("Example.com", "EXAMPLE.COM")).toBe(false)
				expect(isDomainMatch("App.Example.COM", "auth.example.com")).toBe(false)
				// Same case should work
				expect(isDomainMatch("app.example.com", "auth.example.com")).toBe(true)
			})

			it("should handle numeric domains", () => {
				expect(isDomainMatch("app.123domain.com", "api.123domain.com")).toBe(true)
				expect(isDomainMatch("site1.example.com", "site2.example.com")).toBe(true)
			})

			it("should handle hyphenated domains", () => {
				expect(isDomainMatch("app.my-company.com", "auth.my-company.com")).toBe(true)
				expect(isDomainMatch("test-app.example.com", "prod-app.example.com")).toBe(true)
			})
		})

		describe("Security Scenarios", () => {
			it("should prevent subdomain hijacking attempts", () => {
				expect(isDomainMatch("malicious.com", "app.example.com")).toBe(false)
				expect(isDomainMatch("evil.badsite.com", "app.goodsite.com")).toBe(false)
			})

			it("should prevent homograph attacks", () => {
				expect(isDomainMatch("examp1e.com", "example.com")).toBe(false)
				expect(isDomainMatch("goog1e.com", "google.com")).toBe(false)
			})

			it("should handle legitimate multi-tenant scenarios", () => {
				expect(isDomainMatch("tenant1.saas.com", "tenant2.saas.com")).toBe(true)
				expect(isDomainMatch("client-a.platform.co.uk", "client-b.platform.co.uk")).toBe(true)
			})
		})

		describe("Edge Cases", () => {
			it("should handle empty and whitespace domains", () => {
				expect(isDomainMatch("", "")).toBe(true)
				expect(isDomainMatch("example.com", "")).toBe(false)
				expect(isDomainMatch("", "example.com")).toBe(false)
			})

			it("should handle domains with trailing dots", () => {
				expect(isDomainMatch("example.com.", "example.com")).toBe(false) // Different strings
				expect(isDomainMatch("example.com.", "example.com.")).toBe(true) // Same strings
			})

			it("should handle very long domains", () => {
				const longSubdomain = "a".repeat(50)
				expect(isDomainMatch(`${longSubdomain}.example.com`, "app.example.com")).toBe(true)
			})

			it("should handle international domains", () => {
				expect(isDomainMatch("тест.example.com", "приложение.example.com")).toBe(true)
				expect(isDomainMatch("测试.example.com", "应用.example.com")).toBe(true)
			})
		})
	})

	describe("lazy", () => {
		it("should execute function only once", () => {
			const mockFn = vi.fn(() => "computed value")
			const lazyFn = lazy(mockFn)

			// First call
			const result1 = lazyFn()
			expect(result1).toBe("computed value")
			expect(mockFn).toHaveBeenCalledTimes(1)

			// Second call
			const result2 = lazyFn()
			expect(result2).toBe("computed value")
			expect(mockFn).toHaveBeenCalledTimes(1) // Still only called once

			// Third call
			const result3 = lazyFn()
			expect(result3).toBe("computed value")
			expect(mockFn).toHaveBeenCalledTimes(1) // Still only called once
		})

		it("should cache complex objects", () => {
			const complexObject = {
				data: [1, 2, 3],
				nested: {
					value: "test",
					computed: Math.random()
				}
			}

			const mockFn = vi.fn(() => complexObject)
			const lazyFn = lazy(mockFn)

			const result1 = lazyFn()
			const result2 = lazyFn()

			expect(result1).toBe(result2) // Same reference
			expect(result1).toEqual(complexObject)
			expect(mockFn).toHaveBeenCalledTimes(1)
		})

		it("should handle functions that return primitives", () => {
			const numberFn = lazy(() => 42)
			const stringFn = lazy(() => "hello")
			const booleanFn = lazy(() => true)
			const nullFn = lazy(() => null)
			const undefinedFn = lazy(() => undefined)

			expect(numberFn()).toBe(42)
			expect(numberFn()).toBe(42) // Cached

			expect(stringFn()).toBe("hello")
			expect(stringFn()).toBe("hello") // Cached

			expect(booleanFn()).toBe(true)
			expect(booleanFn()).toBe(true) // Cached

			expect(nullFn()).toBe(null)
			expect(nullFn()).toBe(null) // Cached

			expect(undefinedFn()).toBe(undefined)
			expect(undefinedFn()).toBe(undefined) // Cached
		})

		it("should handle expensive computations", () => {
			let computationCount = 0
			const expensiveComputation = lazy(() => {
				computationCount++
				// Simulate expensive work
				let sum = 0
				for (let i = 0; i < 1000; i++) {
					sum += i
				}
				return sum
			})

			const result1 = expensiveComputation()
			expect(computationCount).toBe(1)
			expect(result1).toBe(499500) // Sum of 0 to 999

			const result2 = expensiveComputation()
			expect(computationCount).toBe(1) // Still only computed once
			expect(result2).toBe(499500)
		})

		it("should handle functions with side effects", () => {
			let sideEffectCount = 0
			const fnWithSideEffects = lazy(() => {
				sideEffectCount++
				console.log("Side effect executed") // This should only happen once
				return "result"
			})

			fnWithSideEffects()
			fnWithSideEffects()
			fnWithSideEffects()

			expect(sideEffectCount).toBe(1)
		})

		it("should handle functions that throw errors", () => {
			const errorFn = lazy(() => {
				throw new Error("Computation failed")
			})

			expect(() => errorFn()).toThrow("Computation failed")
			expect(() => errorFn()).toThrow("Computation failed") // Should throw again
		})

		it("should handle async-like patterns", () => {
			const asyncLikeData = {
				promise: Promise.resolve("async result"),
				timestamp: Date.now()
			}

			const lazyAsync = lazy(() => asyncLikeData)

			const result1 = lazyAsync()
			const result2 = lazyAsync()

			expect(result1).toBe(result2)
			expect(result1.promise).toBe(asyncLikeData.promise)
			expect(result1.timestamp).toBe(asyncLikeData.timestamp)
		})

		it("should work with different return types", () => {
			// Array
			const arrayFn = lazy(() => [1, 2, 3])
			expect(arrayFn()).toEqual([1, 2, 3])
			expect(arrayFn()).toBe(arrayFn()) // Same reference

			// Object
			const objectFn = lazy(() => ({ key: "value" }))
			expect(objectFn()).toEqual({ key: "value" })
			expect(objectFn()).toBe(objectFn()) // Same reference

			// Function
			const functionFn = lazy(() => () => "inner function")
			expect(typeof functionFn()).toBe("function")
			expect(functionFn()()).toBe("inner function")
			expect(functionFn()).toBe(functionFn()) // Same reference
		})

		it("should handle multiple independent lazy functions", () => {
			const lazy1 = lazy(() => "first")
			const lazy2 = lazy(() => "second")
			const lazy3 = lazy(() => "third")

			expect(lazy1()).toBe("first")
			expect(lazy2()).toBe("second")
			expect(lazy3()).toBe("third")

			// Each should maintain independent state
			expect(lazy1()).toBe("first")
			expect(lazy2()).toBe("second")
			expect(lazy3()).toBe("third")
		})

		it("should handle nested lazy functions", () => {
			const outerLazy = lazy(() => {
				const innerLazy = lazy(() => "inner value")
				return {
					getInner: innerLazy,
					direct: "outer value"
				}
			})

			const result1 = outerLazy()
			const result2 = outerLazy()

			expect(result1).toBe(result2) // Same outer object
			expect(result1.direct).toBe("outer value")
			expect(result1.getInner()).toBe("inner value")
			expect(result1.getInner()).toBe("inner value") // Inner also cached
		})
	})

	describe("Performance", () => {
		it("should handle high-frequency URL construction", () => {
			const ctx = createMockContext("https://example.com/auth", {
				"x-forwarded-host": "api.example.com",
				"x-forwarded-proto": "https"
			})

			const iterations = 1000
			const start = Date.now()

			for (let i = 0; i < iterations; i++) {
				getRelativeUrl(ctx, `./callback${i}`)
			}

			const duration = Date.now() - start
			expect(duration).toBeLessThan(100) // Should be very fast
		})

		it("should handle many domain comparisons efficiently", () => {
			const domains = Array.from({ length: 1000 }, (_, i) => `sub${i}.example.com`)

			const start = Date.now()

			for (let i = 0; i < domains.length; i++) {
				for (let j = i + 1; j < Math.min(i + 10, domains.length); j++) {
					isDomainMatch(domains[i], domains[j])
				}
			}

			const duration = Date.now() - start
			expect(duration).toBeLessThan(500) // Should handle many comparisons quickly
		})

		it("should handle many lazy function calls efficiently", () => {
			const lazyFn = lazy(() => "cached value")

			const start = Date.now()

			for (let i = 0; i < 10000; i++) {
				lazyFn()
			}

			const duration = Date.now() - start
			expect(duration).toBeLessThan(50) // Cached calls should be very fast
		})
	})

	describe("Integration Scenarios", () => {
		it("should work together in OAuth callback scenario", () => {
			// Simulate OAuth callback URL construction with domain validation
			const ctx = createMockContext("http://app-internal:3000/auth/github", {
				"x-forwarded-host": "myapp.com",
				"x-forwarded-proto": "https"
			})

			const callbackUrl = getRelativeUrl(ctx, "./callback")
			expect(callbackUrl).toBe("https://myapp.com:3000/auth/callback")

			// Validate that callback domain matches app domain
			const appDomain = "app.myapp.com"
			const callbackDomain = new URL(callbackUrl).hostname

			expect(isDomainMatch(appDomain, callbackDomain)).toBe(true)
		})

		it("should handle multi-tenant application scenarios", () => {
			// Different tenants on same platform
			const tenant1Domain = "tenant1.platform.com"
			const tenant2Domain = "tenant2.platform.com"
			const platformDomain = "admin.platform.com"

			expect(isDomainMatch(tenant1Domain, platformDomain)).toBe(true)
			expect(isDomainMatch(tenant2Domain, platformDomain)).toBe(true)
			expect(isDomainMatch(tenant1Domain, tenant2Domain)).toBe(true)
		})

		it("should cache expensive configuration loading", () => {
			const loadConfig = lazy(() => {
				// Simulate expensive config loading
				return {
					apiUrl: "https://api.example.com",
					features: ["feature1", "feature2"],
					secrets: {
						clientId: "secret_client_id",
						clientSecret: "secret_client_secret"
					}
				}
			})

			// Multiple parts of application request config
			const config1 = loadConfig()
			const config2 = loadConfig()
			const config3 = loadConfig()

			expect(config1).toBe(config2)
			expect(config2).toBe(config3)
			expect(config1.apiUrl).toBe("https://api.example.com")
		})
	})
})
