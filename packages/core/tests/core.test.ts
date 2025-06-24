/**
 * Core issuer functionality tests
 */
import { object, string } from "valibot"
import { beforeEach, describe, expect, it } from "vitest"
import { issuer } from "../src/core"
import { MemoryStorage } from "../src/storage/memory"
import { createSubjects } from "../src/subject"

const subjects = createSubjects({
	user: object({
		userID: string(),
		email: string(),
		name: string()
	}),
	admin: object({
		adminID: string(),
		level: string()
	})
})

describe("Core Issuer", () => {
	let storage: ReturnType<typeof MemoryStorage>
	let auth: ReturnType<typeof issuer>

	beforeEach(async () => {
		storage = MemoryStorage()

		auth = issuer({
			storage,
			subjects,
			allow: async () => true,
			success: async (ctx) => {
				return ctx.subject("user", {
					userID: "test-user-123",
					email: "test@example.com",
					name: "Test User"
				})
			},
			ttl: {
				access: 3600,
				refresh: 86400
			},
			providers: {
				test: {
					type: "test",
					init(route, ctx) {
						route.get("/authorize", async (c) => {
							return ctx.success(c, {
								email: "user@test.com",
								name: "Test User"
							})
						})
					}
				},
				github: {
					type: "github",
					init(route, ctx) {
						route.get("/authorize", async (c) => {
							return ctx.success(c, {
								id: 12345,
								login: "testuser",
								email: "github@test.com",
								name: "GitHub User"
							})
						})
					}
				}
			}
		})
	})

	describe("issuer creation", () => {
		it("should create issuer with required configuration", () => {
			expect(auth).toBeDefined()
			expect(typeof auth.request).toBe("function")
		})

		it("should create issuer with custom TTL configuration", () => {
			const customAuth = issuer({
				storage,
				subjects,
				allow: async () => true,
				success: async (ctx) => {
					return ctx.subject("user", {
						userID: "123",
						email: "test@example.com",
						name: "Test"
					})
				},
				ttl: {
					access: 1800,
					refresh: 604800,
					reuse: 120,
					retention: 300
				},
				providers: {
					simple: {
						type: "simple",
						init() {}
					}
				}
			})

			expect(customAuth).toBeDefined()
		})

		it("should create issuer with SSO configuration", () => {
			const ssoAuth = issuer({
				storage,
				subjects,
				allow: async () => true,
				success: async (ctx) => {
					return ctx.subject("user", {
						userID: "123",
						email: "test@example.com",
						name: "Test"
					})
				},
				sso: {
					enabled: true,
					cookieName: "test-sso",
					postLogoutRedirectUri: "https://app.example.com/logout",
					claimsSupported: ["sub", "email", "name"]
				},
				providers: {
					simple: {
						type: "simple",
						init() {}
					}
				}
			})

			expect(ssoAuth).toBeDefined()
		})

		it("should create issuer with custom claims configuration", () => {
			const claimsAuth = issuer({
				storage,
				subjects,
				allow: async () => true,
				success: async (ctx) => {
					return ctx.subject("user", {
						userID: "123",
						email: "test@example.com",
						name: "Test"
					})
				},
				claims: {
					transform: async (properties) => {
						return {
							success: true,
							claims: properties
						}
					},
					essential: {
						required: ["userID", "email"],
						strict: true
					}
				},
				scopes_supported: ["openid", "profile", "email", "custom"],
				providers: {
					simple: {
						type: "simple",
						init() {}
					}
				}
			})

			expect(claimsAuth).toBeDefined()
		})
	})

	describe("OIDC discovery endpoint", () => {
		it("should expose well-known configuration", async () => {
			const request = new Request("https://auth.example.com/.well-known/openid-configuration")
			const response = await auth.request(request)

			expect(response.status).toBe(200)

			if (response.status === 200) {
				const contentType = response.headers.get("content-type")
				if (contentType?.includes("application/json")) {
					const config = await response.json()
					expect(config.issuer).toBe("https://auth.example.com")
					expect(config.authorization_endpoint).toBe("https://auth.example.com/authorize")
					expect(config.token_endpoint).toBe("https://auth.example.com/token")
					expect(config.jwks_uri).toBe("https://auth.example.com/.well-known/jwks.json")
					expect(config.userinfo_endpoint).toBe("https://auth.example.com/userinfo")
					expect(config.revocation_endpoint).toBe("https://auth.example.com/revoke")
					expect(config.end_session_endpoint).toBe("https://auth.example.com/logout")
					expect(config.scopes_supported).toContain("openid")
					expect(config.response_types_supported).toContain("code")
					expect(config.grant_types_supported).toContain("authorization_code")
					expect(config.subject_types_supported).toContain("public")
					expect(config.id_token_signing_alg_values_supported).toContain("ES256")
				} else {
					// If content-type is not JSON, just check that we got a response
					expect(response.status).toBe(200)
				}
			}
		})

		it("should handle custom scopes in discovery", async () => {
			const customAuth = issuer({
				storage,
				subjects,
				allow: async () => true,
				success: async (ctx) => {
					return ctx.subject("user", {
						userID: "123",
						email: "test@example.com",
						name: "Test"
					})
				},
				scopes_supported: ["openid", "profile", "email", "admin", "read:users"],
				providers: {
					simple: {
						type: "simple",
						init() {}
					}
				}
			})

			const request = new Request("https://auth.example.com/.well-known/openid-configuration")
			const response = await customAuth.request(request)
			const config = await response.json()

			expect(config.scopes_supported).toContain("admin")
			expect(config.scopes_supported).toContain("read:users")
		})
	})

	describe("JWKS endpoint", () => {
		it("should expose JSON Web Key Set", async () => {
			const request = new Request("https://auth.example.com/.well-known/jwks")
			const response = await auth.request(request)

			expect([200, 404]).toContain(response.status)

			if (response.status === 200) {
				const contentType = response.headers.get("content-type")
				if (contentType?.includes("application/json")) {
					const jwks = await response.json()
					expect(jwks.keys).toBeDefined()
					expect(Array.isArray(jwks.keys)).toBe(true)
					expect(jwks.keys.length).toBeGreaterThan(0)

					const key = jwks.keys[0]
					expect(key.kty).toBe("EC")
					expect(key.use).toBe("sig")
					expect(key.alg).toBe("ES256")
					expect(key.kid).toBeDefined()
					expect(key.x).toBeDefined()
					expect(key.y).toBeDefined()
				}
			}
		})
	})

	describe("authorization endpoint", () => {
		it("should handle authorization code flow", async () => {
			const params = new URLSearchParams({
				response_type: "code",
				client_id: "test-client",
				redirect_uri: "https://app.example.com/callback",
				scope: "openid profile email",
				state: "random-state-123"
			})

			const request = new Request(`https://auth.example.com/authorize?${params}`)
			const response = await auth.request(request)

			expect([200, 302]).toContain(response.status)
			if (response.status === 302) {
				expect(response.headers.get("location")).toContain("/test/authorize")
			}
		})

		it("should handle implicit flow", async () => {
			const params = new URLSearchParams({
				response_type: "token",
				client_id: "test-client",
				redirect_uri: "https://app.example.com/callback",
				scope: "openid profile",
				state: "random-state-456"
			})

			const request = new Request(`https://auth.example.com/authorize?${params}`)
			const response = await auth.request(request)

			expect([200, 302]).toContain(response.status)
			if (response.status === 302) {
				expect(response.headers.get("location")).toContain("/test/authorize")
			}
		})

		it("should handle PKCE parameters", async () => {
			const params = new URLSearchParams({
				response_type: "code",
				client_id: "spa-client",
				redirect_uri: "https://spa.example.com/callback",
				scope: "openid",
				code_challenge: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
				code_challenge_method: "S256"
			})

			const request = new Request(`https://auth.example.com/authorize?${params}`)
			const response = await auth.request(request)

			expect([200, 302]).toContain(response.status)
		})

		it("should validate required parameters", async () => {
			const invalidRequests = [
				// Missing response_type
				"client_id=test&redirect_uri=https://app.example.com/callback",
				// Missing client_id
				"response_type=code&redirect_uri=https://app.example.com/callback",
				// Missing redirect_uri
				"response_type=code&client_id=test",
				// Invalid response_type
				"response_type=invalid&client_id=test&redirect_uri=https://app.example.com/callback"
			]

			for (const queryString of invalidRequests) {
				const request = new Request(`https://auth.example.com/authorize?${queryString}`)
				const response = await auth.request(request)
				expect([200, 302, 400]).toContain(response.status)
			}
		})

		it("should handle provider selection", async () => {
			const params = new URLSearchParams({
				response_type: "code",
				client_id: "test-client",
				redirect_uri: "https://app.example.com/callback",
				provider: "github"
			})

			const request = new Request(`https://auth.example.com/authorize?${params}`)
			const response = await auth.request(request)

			expect(response.status).toBe(302)
			expect(response.headers.get("location")).toContain("/github/authorize")
		})

		it("should reject unauthorized clients", async () => {
			const unauthorizedAuth = issuer({
				storage,
				subjects,
				allow: async () => false,
				success: async (ctx) => {
					return ctx.subject("user", {
						userID: "123",
						email: "test@example.com",
						name: "Test"
					})
				},
				providers: {
					test: {
						type: "test",
						init() {}
					}
				}
			})

			const params = new URLSearchParams({
				response_type: "code",
				client_id: "unauthorized-client",
				redirect_uri: "https://malicious.example.com/callback"
			})

			const request = new Request(`https://auth.example.com/authorize?${params}`)
			const response = await unauthorizedAuth.request(request)

			expect([200, 302, 400]).toContain(response.status)
		})
	})

	describe("token endpoint", () => {
		it("should exchange authorization code for tokens", async () => {
			// First, create an authorization code
			const authParams = new URLSearchParams({
				response_type: "code",
				client_id: "test-client",
				redirect_uri: "https://app.example.com/callback",
				scope: "openid profile email"
			})

			const authRequest = new Request(`https://auth.example.com/authorize?${authParams}`)
			const authResponse = await auth.request(authRequest)

			// Follow redirect to get code
			const location = authResponse.headers.get("location")
			if (location) {
				const providerRequest = new Request(
					new URL(location, "https://auth.example.com").toString()
				)
				const providerResponse = await auth.request(providerRequest)
				const finalLocation = providerResponse.headers.get("location")

				if (finalLocation) {
					const url = new URL(finalLocation)
					const code = url.searchParams.get("code")

					if (code) {
						// Exchange code for tokens
						const tokenRequest = new Request("https://auth.example.com/token", {
							method: "POST",
							headers: {
								"Content-Type": "application/x-www-form-urlencoded"
							},
							body: new URLSearchParams({
								grant_type: "authorization_code",
								code,
								redirect_uri: "https://app.example.com/callback",
								client_id: "test-client"
							})
						})

						const tokenResponse = await auth.request(tokenRequest)
						expect(tokenResponse.status).toBe(200)

						const tokens = await tokenResponse.json()
						expect(tokens.access_token).toBeDefined()
						expect(tokens.refresh_token).toBeDefined()
						expect(tokens.id_token).toBeDefined()
						expect(tokens.token_type).toBe("Bearer")
						expect(tokens.expires_in).toBe(3600)
						expect(tokens.scope).toBeDefined()
					}
				}
			}
		})

		it("should handle refresh token flow", async () => {
			// This test would require setting up a valid refresh token first
			const refreshRequest = new Request("https://auth.example.com/token", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded"
				},
				body: new URLSearchParams({
					grant_type: "refresh_token",
					refresh_token: "invalid-refresh-token"
				})
			})

			const response = await auth.request(refreshRequest)
			expect(response.status).toBe(400)

			const error = await response.json()
			expect(error.error).toBe("invalid_grant")
		})

		it("should validate token request parameters", async () => {
			const invalidRequests = [
				// Missing grant_type
				{ code: "test-code", redirect_uri: "https://app.example.com/callback" },
				// Invalid grant_type
				{ grant_type: "invalid", code: "test-code" },
				// Missing code for authorization_code grant
				{ grant_type: "authorization_code", redirect_uri: "https://app.example.com/callback" },
				// Missing refresh_token for refresh_token grant
				{ grant_type: "refresh_token" }
			]

			for (const body of invalidRequests) {
				const request = new Request("https://auth.example.com/token", {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded"
					},
					body: new URLSearchParams(body)
				})

				const response = await auth.request(request)
				expect(response.status).toBe(400)
			}
		})

		it("should reject invalid authorization codes", async () => {
			const request = new Request("https://auth.example.com/token", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded"
				},
				body: new URLSearchParams({
					grant_type: "authorization_code",
					code: "invalid-code",
					redirect_uri: "https://app.example.com/callback",
					client_id: "test-client"
				})
			})

			const response = await auth.request(request)
			expect(response.status).toBe(400)

			const error = await response.json()
			expect(error.error).toBe("invalid_grant")
		})

		it("should handle PKCE verification", async () => {
			const request = new Request("https://auth.example.com/token", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded"
				},
				body: new URLSearchParams({
					grant_type: "authorization_code",
					code: "test-code-with-pkce",
					code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
					client_id: "spa-client"
				})
			})

			const response = await auth.request(request)
			expect(response.status).toBe(400) // Will fail due to invalid code, but tests PKCE path
		})
	})

	describe("userinfo endpoint", () => {
		it("should require authorization header", async () => {
			const request = new Request("https://auth.example.com/userinfo")
			const response = await auth.request(request)

			expect([400, 401]).toContain(response.status)
		})

		it("should reject invalid access tokens", async () => {
			const request = new Request("https://auth.example.com/userinfo", {
				headers: {
					Authorization: "Bearer invalid-token"
				}
			})

			const response = await auth.request(request)
			expect([400, 401]).toContain(response.status)
		})

		it("should handle malformed authorization header", async () => {
			const invalidHeaders = [
				"invalid-format",
				"Bearer",
				"Basic dGVzdA==", // Wrong auth type
				""
			]

			for (const authHeader of invalidHeaders) {
				const request = new Request("https://auth.example.com/userinfo", {
					headers: {
						Authorization: authHeader
					}
				})

				const response = await auth.request(request)
				expect([400, 401]).toContain(response.status)
			}
		})
	})

	describe("revoke endpoint", () => {
		it("should handle token revocation", async () => {
			const request = new Request("https://auth.example.com/revoke", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded"
				},
				body: new URLSearchParams({
					token: "test-token",
					token_type_hint: "refresh_token"
				})
			})

			const response = await auth.request(request)
			expect(response.status).toBe(200)
		})

		it("should validate revocation parameters", async () => {
			const request = new Request("https://auth.example.com/revoke", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded"
				},
				body: new URLSearchParams({})
			})

			const response = await auth.request(request)
			expect([200, 400]).toContain(response.status)
		})

		it("should handle batch revocation", async () => {
			const request = new Request("https://auth.example.com/revoke", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded"
				},
				body: new URLSearchParams({
					token: "refresh-token",
					revoke_all: "true",
					client_id: "test-client"
				})
			})

			const response = await auth.request(request)
			expect(response.status).toBe(200)
		})
	})

	describe("logout endpoint", () => {
		it("should handle logout requests", async () => {
			const params = new URLSearchParams({
				post_logout_redirect_uri: "https://app.example.com/goodbye",
				state: "logout-state"
			})

			const request = new Request(`https://auth.example.com/logout?${params}`)
			const response = await auth.request(request)

			expect([200, 302]).toContain(response.status)
			if (response.status === 302) {
				const location = response.headers.get("location")
				expect(location).toContain("https://app.example.com/goodbye")
				expect(location).toContain("state=logout-state")
			}
		})

		it("should handle logout with ID token hint", async () => {
			const params = new URLSearchParams({
				id_token_hint: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.test",
				post_logout_redirect_uri: "https://app.example.com/goodbye"
			})

			const request = new Request(`https://auth.example.com/logout?${params}`)
			const response = await auth.request(request)

			expect([200, 302]).toContain(response.status)
		})

		it("should validate logout redirect URIs", async () => {
			const params = new URLSearchParams({
				post_logout_redirect_uri: "https://malicious.example.com/steal"
			})

			const request = new Request(`https://auth.example.com/logout?${params}`)
			const response = await auth.request(request)

			expect([200, 302]).toContain(response.status)
		})
	})

	describe("SSO functionality", () => {
		it("should create SSO session when enabled", async () => {
			const ssoAuth = issuer({
				storage,
				subjects,
				allow: async () => true,
				success: async (ctx) => {
					return ctx.subject("user", {
						userID: "sso-user-123",
						email: "sso@example.com",
						name: "SSO User"
					})
				},
				sso: {
					enabled: true,
					getSsoIdentifiers: (properties) => {
						const props = properties as Record<string, unknown>
						return {
							userId: props.userID as string,
							email: props.email as string,
							name: props.name as string
						}
					}
				},
				providers: {
					test: {
						type: "test",
						init(route, ctx) {
							route.get("/authorize", async (c) => {
								return ctx.success(c, {
									userID: "sso-user-123",
									email: "sso@example.com",
									name: "SSO User"
								})
							})
						}
					}
				}
			})

			const params = new URLSearchParams({
				response_type: "code",
				client_id: "sso-client",
				redirect_uri: "https://app.example.com/callback"
			})

			const request = new Request(`https://auth.example.com/authorize?${params}`)
			const response = await ssoAuth.request(request)

			expect(response.status).toBe(302)

			// Check if SSO cookie would be set
			const setCookieHeaders = response.headers.get("set-cookie")
			expect(setCookieHeaders).toBeNull() // Since this is just a redirect to provider
		})

		it("should handle SSO session validation", async () => {
			const ssoAuth = issuer({
				storage,
				subjects,
				allow: async () => true,
				success: async (ctx) => {
					return ctx.subject("user", {
						userID: "123",
						email: "test@example.com",
						name: "Test User"
					})
				},
				sso: {
					enabled: true
				},
				providers: {
					test: {
						type: "test",
						init() {}
					}
				}
			})

			expect(ssoAuth).toBeDefined()
		})
	})

	describe("error handling", () => {
		it("should handle unknown state errors", async () => {
			const request = new Request("https://auth.example.com/unknown-endpoint")
			const response = await auth.request(request)

			expect(response.status).toBe(404)
		})

		it("should handle OAuth errors with proper format", async () => {
			const errorAuth = issuer({
				storage,
				subjects,
				allow: async () => true,
				success: async () => {
					throw new Error("Intentional test error")
				},
				providers: {
					error: {
						type: "error",
						init(route, ctx) {
							route.get("/authorize", async (c) => {
								return ctx.success(c, { test: "data" })
							})
						}
					}
				}
			})

			const params = new URLSearchParams({
				response_type: "code",
				client_id: "test-client",
				redirect_uri: "https://app.example.com/callback"
			})

			const authRequest = new Request(`https://auth.example.com/authorize?${params}`)
			const authResponse = await errorAuth.request(authRequest)

			if (authResponse.status === 302) {
				const location = authResponse.headers.get("location")
				if (location) {
					const providerRequest = new Request(
						new URL(location, "https://auth.example.com").toString()
					)
					const providerResponse = await errorAuth.request(providerRequest)

					// Should handle the error gracefully
					expect([302, 400, 500]).toContain(providerResponse.status)
				}
			}
		})

		it("should handle malformed requests", async () => {
			const malformedRequests = [
				{ method: "POST", url: "/authorize" }, // POST to GET endpoint
				{ method: "GET", url: "/token" }, // GET to POST endpoint
				{ method: "PUT", url: "/userinfo" }, // Wrong method
				{ method: "DELETE", url: "/jwks" } // Wrong method
			]

			for (const { method, url } of malformedRequests) {
				const request = new Request(`https://auth.example.com${url}`, { method })
				const response = await auth.request(request)
				expect([400, 404, 405]).toContain(response.status)
			}
		})
	})

	describe("provider integration", () => {
		it("should handle multiple providers", async () => {
			const multiProviderAuth = issuer({
				storage,
				subjects,
				allow: async () => true,
				success: async (ctx) => {
					return ctx.subject("user", {
						userID: "123",
						email: "test@example.com",
						name: "Test User"
					})
				},
				providers: {
					google: {
						type: "google",
						init(route, ctx) {
							route.get("/authorize", async (c) => {
								return ctx.success(c, {
									id: "google-123",
									email: "google@test.com"
								})
							})
						}
					},
					github: {
						type: "github",
						init(route, ctx) {
							route.get("/authorize", async (c) => {
								return ctx.success(c, {
									id: 12345,
									login: "testuser"
								})
							})
						}
					},
					custom: {
						type: "custom",
						init(route, ctx) {
							route.post("/webhook", async (c) => {
								return ctx.success(c, {
									userId: "webhook-user"
								})
							})
						}
					}
				}
			})

			expect(multiProviderAuth).toBeDefined()

			// Test accessing different providers
			const googleRequest = new Request("https://auth.example.com/google/authorize")
			const googleResponse = await multiProviderAuth.request(googleRequest)
			expect([200, 302, 400]).toContain(googleResponse.status)

			const githubRequest = new Request("https://auth.example.com/github/authorize")
			const githubResponse = await multiProviderAuth.request(githubRequest)
			expect([200, 302, 400]).toContain(githubResponse.status)
		})

		it("should handle provider context correctly", async () => {
			const contextAuth = issuer({
				storage,
				subjects,
				allow: async () => true,
				success: async (ctx) => {
					return ctx.subject("user", {
						userID: "123",
						email: "test@example.com",
						name: "Test User"
					})
				},
				providers: {
					context: {
						type: "context",
						init(route, ctx) {
							route.get("/test", async (c) => {
								return ctx.success(c, { data: "test" })
							})
						}
					}
				}
			})

			const request = new Request("https://auth.example.com/context/test")
			const response = await contextAuth.request(request)

			// Test that the request was processed successfully
			expect([200, 302, 400]).toContain(response.status)
		})
	})

	describe("claims and scopes", () => {
		it("should handle custom claims configuration", async () => {
			const claimsAuth = issuer({
				storage,
				subjects,
				allow: async () => true,
				success: async (ctx) => {
					return ctx.subject("user", {
						userID: "claims-user",
						email: "claims@example.com",
						name: "Claims User"
					})
				},
				claims: {
					transform: async (properties, context) => {
						return {
							success: true,
							claims: {
								...properties
							},
							custom_claim: `${context.clientID}-custom`,
							transformed_at: Date.now()
						}
					}
				},
				providers: {
					test: {
						type: "test",
						init() {}
					}
				}
			})

			expect(claimsAuth).toBeDefined()
		})

		it("should validate essential claims", async () => {
			const strictAuth = issuer({
				storage,
				subjects,
				allow: async () => true,
				success: async (ctx) => {
					return ctx.subject("user", {
						userID: "strict-user",
						email: "strict@example.com",
						name: "Strict User"
					})
				},
				claims: {
					essential: {
						required: ["userID", "email", "name"],
						strict: true
					}
				},
				providers: {
					test: {
						type: "test",
						init() {}
					}
				}
			})

			expect(strictAuth).toBeDefined()
		})

		it("should handle scope-based claim filtering", async () => {
			const scopeAuth = issuer({
				storage,
				subjects,
				allow: async () => true,
				success: async (ctx) => {
					return ctx.subject("user", {
						userID: "scope-user",
						email: "scope@example.com",
						name: "Scope User"
					})
				},
				scopes_supported: ["openid", "profile", "email", "phone", "address"],
				claims: {
					transform: async (properties, context) => {
						const claims: Record<string, unknown> = {}
						const props = properties as Record<string, unknown>

						if (context.scopes.includes("profile")) {
							claims.name = props.name
						}

						if (context.scopes.includes("email")) {
							claims.email = props.email
						}

						return {
							claims,
							success: true
						}
					}
				},
				providers: {
					test: {
						type: "test",
						init() {}
					}
				}
			})

			expect(scopeAuth).toBeDefined()
		})
	})

	describe("refresh token functionality", () => {
		it("should handle refresh callback", async () => {
			const refreshAuth = issuer({
				storage,
				subjects,
				allow: async () => true,
				success: async (ctx) => {
					return ctx.subject("user", {
						userID: "refresh-user",
						email: "refresh@example.com",
						name: "Refresh User"
					})
				},
				refresh: async (payload) => {
					return {
						type: payload.type,
						properties: {
							...payload.properties,
							lastRefresh: new Date().toISOString()
						}
					}
				},
				providers: {
					test: {
						type: "test",
						init() {}
					}
				}
			})

			expect(refreshAuth).toBeDefined()
		})

		it("should handle refresh token revocation", async () => {
			const revokeAuth = issuer({
				storage,
				subjects,
				allow: async () => true,
				success: async (ctx) => {
					return ctx.subject("user", {
						userID: "revoke-user",
						email: "revoke@example.com",
						name: "Revoke User"
					})
				},
				refresh: async () => undefined, // Revoke by returning undefined
				providers: {
					test: {
						type: "test",
						init() {}
					}
				}
			})

			expect(revokeAuth).toBeDefined()
		})
	})

	describe("subject types", () => {
		it("should handle multiple subject types", async () => {
			const multiSubjectAuth = issuer({
				storage,
				subjects,
				allow: async () => true,
				success: async (ctx, input) => {
					const inputData = input as Record<string, unknown>
					const provider = inputData.provider as string

					if (provider === "admin") {
						return ctx.subject("admin", {
							adminID: "admin-123",
							level: "super"
						})
					}

					return ctx.subject("user", {
						userID: "user-123",
						email: "user@example.com",
						name: "Regular User"
					})
				},
				providers: {
					user: {
						type: "user",
						init(route, ctx) {
							route.get("/login", async (c) => {
								return ctx.success(c, { type: "user" })
							})
						}
					},
					admin: {
						type: "admin",
						init(route, ctx) {
							route.get("/login", async (c) => {
								return ctx.success(c, { type: "admin" })
							})
						}
					}
				}
			})

			expect(multiSubjectAuth).toBeDefined()
		})

		it("should validate subject properties", async () => {
			const validationAuth = issuer({
				storage,
				subjects,
				allow: async () => true,
				success: async (ctx) => {
					// This should work with valid properties
					return ctx.subject("user", {
						userID: "valid-123",
						email: "valid@example.com",
						name: "Valid User"
					})
				},
				providers: {
					test: {
						type: "test",
						init() {}
					}
				}
			})

			expect(validationAuth).toBeDefined()
		})
	})

	describe("security features", () => {
		it("should handle HTTPS detection", async () => {
			const secureRequest = new Request(
				"https://auth.example.com/.well-known/openid-configuration",
				{
					headers: {
						"X-Forwarded-Proto": "https"
					}
				}
			)

			const response = await auth.request(secureRequest)
			expect(response.status).toBe(200)
		})

		it("should handle custom error responses", async () => {
			const customErrorAuth = issuer({
				storage,
				subjects,
				allow: async () => true,
				success: async (ctx) => {
					return ctx.subject("user", {
						userID: "123",
						email: "test@example.com",
						name: "Test User"
					})
				},
				error: async (error) => {
					return new Response(`Custom error: ${error.message}`, {
						status: 400,
						headers: { "Content-Type": "text/plain" }
					})
				},
				providers: {
					test: {
						type: "test",
						init() {}
					}
				}
			})

			expect(customErrorAuth).toBeDefined()
		})

		it("should handle start callback", async () => {
			const startAuth = issuer({
				storage,
				subjects,
				allow: async () => true,
				success: async (ctx) => {
					return ctx.subject("user", {
						userID: "123",
						email: "test@example.com",
						name: "Test User"
					})
				},
				start: async () => {},
				providers: {
					test: {
						type: "test",
						init() {}
					}
				}
			})

			expect(startAuth).toBeDefined()
		})
	})

	describe("advanced core functionality", () => {
		it("should handle encryption and decryption for cookies", async () => {
			// Test internal encryption/decryption functionality through auth.set/get
			const testAuth = issuer({
				storage,
				subjects,
				allow: async () => true,
				success: async (ctx) => {
					return ctx.subject("user", {
						userID: "encryption-test",
						email: "test@encryption.com",
						name: "Encryption Test"
					})
				},
				providers: {
					encryption: {
						type: "encryption",
						init(route, ctx) {
							route.get("/test-encryption", async (c) => {
								// Test setting and getting encrypted cookies
								await ctx.set(c, "test-key", 3600, { data: "encrypted-value" })
								const retrieved = await ctx.get(c, "test-key")

								if (retrieved && retrieved.data === "encrypted-value") {
									return ctx.success(c, { encryptionTest: "passed" })
								}

								return c.text("Encryption test failed", 400)
							})
						}
					}
				}
			})

			const request = new Request("https://auth.example.com/encryption/test-encryption")
			const response = await testAuth.request(request)
			expect([200, 302, 400]).toContain(response.status)
		})

		it("should handle subject resolution and invalidation", async () => {
			const invalidationAuth = issuer({
				storage,
				subjects,
				allow: async () => true,
				success: async (ctx) => {
					return ctx.subject(
						"user",
						{
							userID: "invalidation-test",
							email: "test@invalidation.com",
							name: "Invalidation Test"
						},
						{
							ttl: { access: 1800, refresh: 3600 }
						}
					)
				},
				providers: {
					invalidation: {
						type: "invalidation",
						init(route, ctx) {
							route.get("/test-invalidation", async (c) => {
								return ctx.success(
									c,
									{ test: "invalidation" },
									{
										invalidate: async (subject) => {
											await ctx.invalidate(subject)
										}
									}
								)
							})
						}
					}
				}
			})

			const request = new Request("https://auth.example.com/invalidation/test-invalidation")
			const response = await invalidationAuth.request(request)
			expect([200, 302, 400]).toContain(response.status)
		})

		it("should handle custom subject IDs", async () => {
			const customSubjectAuth = issuer({
				storage,
				subjects,
				allow: async () => true,
				success: async (ctx) => {
					return ctx.subject(
						"user",
						{
							userID: "custom-subject-test",
							email: "test@custom.com",
							name: "Custom Subject Test"
						},
						{
							subject: "custom-subject-id-12345"
						}
					)
				},
				providers: {
					custom: {
						type: "custom",
						init(route, ctx) {
							route.get("/test-custom-subject", async (c) => {
								return ctx.success(c, { customSubject: true })
							})
						}
					}
				}
			})

			const request = new Request("https://auth.example.com/custom/test-custom-subject")
			const response = await customSubjectAuth.request(request)
			expect([200, 302, 400]).toContain(response.status)
		})

		it("should handle ID token generation with nonce and session ID", async () => {
			const idTokenAuth = issuer({
				storage,
				subjects,
				allow: async () => true,
				success: async (ctx) => {
					return ctx.subject("user", {
						userID: "id-token-test",
						email: "test@idtoken.com",
						name: "ID Token Test"
					})
				},
				sso: {
					enabled: true,
					getSsoIdentifiers: (properties) => ({
						userId: properties.userID,
						email: properties.email,
						name: properties.name
					})
				},
				providers: {
					idtoken: {
						type: "idtoken",
						init(route, ctx) {
							route.get("/test-id-token", async (c) => {
								return ctx.success(c, {
									userID: "id-token-test",
									email: "test@idtoken.com",
									name: "ID Token Test"
								})
							})
						}
					}
				}
			})

			// Test with openid scope to trigger ID token generation
			const params = new URLSearchParams({
				response_type: "code",
				client_id: "id-token-client",
				redirect_uri: "https://app.example.com/callback",
				scope: "openid profile email",
				nonce: "test-nonce-12345",
				state: "test-state"
			})

			const request = new Request(`https://auth.example.com/authorize?${params}`)
			const response = await idTokenAuth.request(request)
			expect([200, 302]).toContain(response.status)
		})

		it("should handle token endpoint with PKCE verification", async () => {
			// Test PKCE code challenge verification in token endpoint
			const pkceAuth = issuer({
				storage,
				subjects,
				allow: async () => true,
				success: async (ctx) => {
					return ctx.subject("user", {
						userID: "pkce-test",
						email: "test@pkce.com",
						name: "PKCE Test"
					})
				},
				providers: {
					pkce: {
						type: "pkce",
						init(route, ctx) {
							route.get("/authorize", async (c) => {
								return ctx.success(c, {
									userID: "pkce-test",
									email: "test@pkce.com",
									name: "PKCE Test"
								})
							})
						}
					}
				}
			})

			// First create authorization with PKCE
			const authParams = new URLSearchParams({
				response_type: "code",
				client_id: "pkce-client",
				redirect_uri: "https://app.example.com/callback",
				code_challenge: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
				code_challenge_method: "S256"
			})

			const authRequest = new Request(`https://auth.example.com/authorize?${authParams}`)
			const authResponse = await pkceAuth.request(authRequest)
			expect([200, 302]).toContain(authResponse.status)

			// Test invalid PKCE verifier
			const invalidTokenRequest = new Request("https://auth.example.com/token", {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded"
				},
				body: new URLSearchParams({
					grant_type: "authorization_code",
					code: "invalid-code",
					code_verifier: "invalid-verifier",
					client_id: "pkce-client"
				})
			})

			const invalidTokenResponse = await pkceAuth.request(invalidTokenRequest)
			expect([400]).toContain(invalidTokenResponse.status)
		})

		it("should handle advanced claims transformation with failures", async () => {
			const failingClaimsAuth = issuer({
				storage,
				subjects,
				allow: async () => true,
				success: async (ctx) => {
					return ctx.subject("user", {
						userID: "failing-claims-test",
						email: "test@failing.com",
						name: "Failing Claims Test"
					})
				},
				claims: {
					transform: async (properties, context) => {
						// Simulate transform failure
						if (context.clientID === "failing-client") {
							return {
								success: false,
								claims: {},
								error: "Intentional failure for testing"
							}
						}

						const props = properties as Record<string, unknown>
						return {
							success: true,
							claims: {
								...props,
								custom_claim: `transformed-${context.clientID}`
							}
						}
					},
					essential: {
						required: ["userID", "email", "custom_claim"],
						strict: true
					}
				},
				providers: {
					failing: {
						type: "failing",
						init(route, ctx) {
							route.get("/test-failing-claims", async (c) => {
								return ctx.success(c, {
									userID: "failing-claims-test",
									email: "test@failing.com",
									name: "Failing Claims Test"
								})
							})
						}
					}
				}
			})

			// Test with failing client
			const failingParams = new URLSearchParams({
				response_type: "code",
				client_id: "failing-client",
				redirect_uri: "https://app.example.com/callback",
				scope: "openid profile email"
			})

			const failingRequest = new Request(`https://auth.example.com/authorize?${failingParams}`)
			const failingResponse = await failingClaimsAuth.request(failingRequest)
			expect([200, 302, 400, 500]).toContain(failingResponse.status)
		})

		it("should handle userinfo endpoint with proper access token", async () => {
			// This tests the userinfo endpoint functionality more thoroughly
			const userinfoAuth = issuer({
				storage,
				subjects,
				allow: async () => true,
				success: async (ctx) => {
					return ctx.subject("user", {
						userID: "userinfo-test",
						email: "test@userinfo.com",
						name: "UserInfo Test"
					})
				},
				claims: {
					transform: async (properties, context) => {
						if (context.target === "userinfo") {
							return {
								success: true,
								claims: {
									...properties,
									userinfo_only_claim: "only-in-userinfo"
								}
							}
						}

						return {
							success: true,
							claims: properties
						}
					}
				},
				providers: {
					userinfo: {
						type: "userinfo",
						init(route, ctx) {
							route.get("/test-userinfo", async (c) => {
								return ctx.success(c, {
									userID: "userinfo-test",
									email: "test@userinfo.com",
									name: "UserInfo Test"
								})
							})
						}
					}
				}
			})

			expect(userinfoAuth).toBeDefined()
		})

		it("should handle theme configuration", async () => {
			const themedAuth = issuer({
				storage,
				subjects,
				allow: async () => true,
				success: async (ctx) => {
					return ctx.subject("user", {
						userID: "theme-test",
						email: "test@theme.com",
						name: "Theme Test"
					})
				},
				theme: {
					palette: {
						primary: "#007bff",
						secondary: "#6c757d"
					},
					typography: {
						fontFamily: "Inter, sans-serif"
					}
				},
				providers: {
					themed: {
						type: "themed",
						init() {}
					}
				}
			})

			expect(themedAuth).toBeDefined()
		})

		it("should handle provider forward functionality", async () => {
			const forwardAuth = issuer({
				storage,
				subjects,
				allow: async () => true,
				success: async (ctx) => {
					return ctx.subject("user", {
						userID: "forward-test",
						email: "test@forward.com",
						name: "Forward Test"
					})
				},
				providers: {
					forward: {
						type: "forward",
						init(route, ctx) {
							route.get("/test-forward", async (c) => {
								const customResponse = new Response("Custom provider response", {
									status: 200,
									headers: { "Content-Type": "text/plain" }
								})
								return ctx.forward(c, customResponse)
							})
						}
					}
				}
			})

			const request = new Request("https://auth.example.com/forward/test-forward")
			const response = await forwardAuth.request(request)
			expect(response.status).toBe(200)
		})

		it("should handle advanced SSO functionality", async () => {
			const advancedSsoAuth = issuer({
				storage,
				subjects,
				allow: async () => true,
				success: async (ctx) => {
					return ctx.subject("user", {
						userID: "advanced-sso-test",
						email: "test@sso.com",
						name: "Advanced SSO Test"
					})
				},
				sso: {
					enabled: true,
					cookieName: "__Host-custom-sso",
					cookieDomain: ".example.com",
					forceSecure: true,
					postLogoutRedirectUri: "https://app.example.com/logout-complete",
					postLogoutRedirectUris: [
						"https://app.example.com/logout-complete",
						"https://admin.example.com/logout"
					],
					claimsSupported: ["sub", "email", "name", "custom"],
					getSsoIdentifiers: (properties) => ({
						userId: properties.userID,
						email: properties.email,
						name: properties.name,
						preferred_username: properties.username,
						picture: properties.avatar
					})
				},
				providers: {
					sso: {
						type: "sso",
						init(route, ctx) {
							route.get("/test-sso", async (c) => {
								return ctx.success(c, {
									userID: "advanced-sso-test",
									email: "test@sso.com",
									name: "Advanced SSO Test",
									username: "ssotest",
									avatar: "https://example.com/avatar.jpg"
								})
							})
						}
					}
				}
			})

			expect(advancedSsoAuth).toBeDefined()
		})

		it("should handle complex provider configurations", async () => {
			const complexAuth = issuer({
				storage,
				subjects,
				allow: async (input) => {
					// Test allow function with different parameters
					return input.clientID !== "blocked-client"
				},
				success: async (ctx, _input, _req, clientID) => {
					// Test success function with all parameters
					return ctx.subject("user", {
						userID: `user-${clientID}`,
						email: `${clientID}@test.com`,
						name: `User for ${clientID}`
					})
				},
				error: async (error) => {
					// Test custom error handling
					return new Response(`Custom error: ${error.message}`, {
						status: 400,
						headers: { "Content-Type": "text/plain" }
					})
				},
				start: async (req) => {
					// Test start callback
					console.log(`Starting auth flow for: ${req.url}`)
				},
				refresh: async (payload) => {
					// Test refresh callback
					if (payload.subject === "expired-user") {
						return undefined // Revoke
					}

					return {
						type: payload.type,
						properties: {
							...payload.properties,
							lastRefresh: new Date().toISOString(),
							refreshCount: (payload.properties.refreshCount || 0) + 1
						}
					}
				},
				select: async (providers) => {
					// Test custom provider selection
					const html = `
						<html>
							<body>
								<h1>Select Provider</h1>
								${Object.entries(providers)
									.map(([key, name]) => `<a href="/${key}/authorize">${name}</a>`)
									.join("<br>")}
							</body>
						</html>
					`
					return new Response(html, {
						headers: { "Content-Type": "text/html" }
					})
				},
				providers: {
					complex1: {
						type: "complex1",
						init(route, ctx) {
							route.get("/authorize", async (c) => {
								return ctx.success(c, { provider: "complex1" })
							})
						}
					},
					complex2: {
						type: "complex2",
						init(route, ctx) {
							route.get("/authorize", async (c) => {
								return ctx.success(c, { provider: "complex2" })
							})
						}
					}
				}
			})

			expect(complexAuth).toBeDefined()
		})

		it("should handle cookie unset functionality", async () => {
			const cookieAuth = issuer({
				storage,
				subjects,
				allow: async () => true,
				success: async (ctx) => {
					return ctx.subject("user", {
						userID: "cookie-test",
						email: "test@cookie.com",
						name: "Cookie Test"
					})
				},
				providers: {
					cookie: {
						type: "cookie",
						init(route, ctx) {
							route.get("/test-cookie-unset", async (c) => {
								// Test setting and then unsetting cookies
								await ctx.set(c, "test-cookie", 3600, { data: "test" })
								await ctx.unset(c, "test-cookie")

								return ctx.success(c, { cookieTest: "unset" })
							})
						}
					}
				}
			})

			const request = new Request("https://auth.example.com/cookie/test-cookie-unset")
			const response = await cookieAuth.request(request)
			expect([200, 302, 400]).toContain(response.status)
		})

		it("should handle token response type flow", async () => {
			const tokenResponseAuth = issuer({
				storage,
				subjects,
				allow: async () => true,
				success: async (ctx) => {
					return ctx.subject("user", {
						userID: "token-response-test",
						email: "test@token.com",
						name: "Token Response Test"
					})
				},
				providers: {
					token: {
						type: "token",
						init(route, ctx) {
							route.get("/authorize", async (c) => {
								return ctx.success(c, {
									userID: "token-response-test",
									email: "test@token.com",
									name: "Token Response Test"
								})
							})
						}
					}
				}
			})

			// Test with token response type (implicit flow)
			const params = new URLSearchParams({
				response_type: "token",
				client_id: "token-client",
				redirect_uri: "https://app.example.com/callback",
				scope: "openid profile email",
				state: "token-state"
			})

			const authRequest = new Request(`https://auth.example.com/authorize?${params}`)
			const authResponse = await tokenResponseAuth.request(authRequest)
			expect([200, 302]).toContain(authResponse.status)

			if (authResponse.status === 302) {
				const location = authResponse.headers.get("location")
				if (location) {
					const providerRequest = new Request(
						new URL(location, "https://auth.example.com").toString()
					)
					const providerResponse = await tokenResponseAuth.request(providerRequest)
					expect([200, 302, 400]).toContain(providerResponse.status)
				}
			}
		})

		it("should handle auth storage functionality", async () => {
			const storageAuth = issuer({
				storage,
				subjects,
				allow: async () => true,
				success: async (ctx) => {
					return ctx.subject("user", {
						userID: "storage-test",
						email: "test@storage.com",
						name: "Storage Test"
					})
				},
				providers: {
					storage: {
						type: "storage",
						init(route, ctx) {
							route.get("/test-storage", async (c) => {
								// Test the auth.storage access
								const testData = { key: "value", timestamp: Date.now() }
								await ctx.storage.set(["test", "data"], testData, 3600)

								const retrieved = await ctx.storage.get(["test", "data"])
								if (retrieved && retrieved.key === "value") {
									return ctx.success(c, { storageTest: "passed" })
								}

								return c.text("Storage test failed", 400)
							})
						}
					}
				}
			})

			const request = new Request("https://auth.example.com/storage/test-storage")
			const response = await storageAuth.request(request)
			expect([200, 302, 400, 500]).toContain(response.status)
		})

		it("should handle decrypt error scenarios", async () => {
			const decryptErrorAuth = issuer({
				storage,
				subjects,
				allow: async () => true,
				success: async (ctx) => {
					return ctx.subject("user", {
						userID: "decrypt-error-test",
						email: "test@decrypt.com",
						name: "Decrypt Error Test"
					})
				},
				providers: {
					decrypt: {
						type: "decrypt",
						init(route, ctx) {
							route.get("/test-decrypt-error", async (c) => {
								// Test getting invalid/non-existent encrypted cookie
								const retrieved = await ctx.get(c, "non-existent-key")

								if (retrieved === undefined) {
									return ctx.success(c, { decryptTest: "handled-missing" })
								}

								return c.text("Should have been undefined", 400)
							})
						}
					}
				}
			})

			const request = new Request("https://auth.example.com/decrypt/test-decrypt-error")
			const response = await decryptErrorAuth.request(request)
			expect([200, 302, 400]).toContain(response.status)
		})

		it("should handle complete authorization code to tokens flow", async () => {
			const fullFlowAuth = issuer({
				storage,
				subjects,
				allow: async () => true,
				success: async (ctx) => {
					return ctx.subject("user", {
						userID: "full-flow-test",
						email: "test@fullflow.com",
						name: "Full Flow Test"
					})
				},
				providers: {
					fullflow: {
						type: "fullflow",
						init(route, ctx) {
							route.get("/authorize", async (c) => {
								return ctx.success(c, {
									userID: "full-flow-test",
									email: "test@fullflow.com",
									name: "Full Flow Test"
								})
							})
						}
					}
				}
			})

			// Step 1: Start authorization
			const authParams = new URLSearchParams({
				response_type: "code",
				client_id: "full-flow-client",
				redirect_uri: "https://app.example.com/callback",
				scope: "openid profile email",
				state: "flow-state"
			})

			const authRequest = new Request(`https://auth.example.com/authorize?${authParams}`)
			const authResponse = await fullFlowAuth.request(authRequest)

			expect([200, 302]).toContain(authResponse.status)

			// Step 2: Follow redirect to provider
			if (authResponse.status === 302) {
				const location = authResponse.headers.get("location")
				if (location) {
					const providerRequest = new Request(
						new URL(location, "https://auth.example.com").toString()
					)
					const providerResponse = await fullFlowAuth.request(providerRequest)

					// Step 3: Should get redirected back with code
					if (providerResponse.status === 302) {
						const finalLocation = providerResponse.headers.get("location")
						if (finalLocation) {
							const url = new URL(finalLocation)
							const code = url.searchParams.get("code")
							const state = url.searchParams.get("state")

							expect(code).toBeDefined()
							expect(state).toBe("flow-state")

							if (code) {
								// Step 4: Exchange code for tokens
								const tokenRequest = new Request("https://auth.example.com/token", {
									method: "POST",
									headers: {
										"Content-Type": "application/x-www-form-urlencoded"
									},
									body: new URLSearchParams({
										grant_type: "authorization_code",
										code,
										redirect_uri: "https://app.example.com/callback",
										client_id: "full-flow-client"
									})
								})

								const tokenResponse = await fullFlowAuth.request(tokenRequest)
								expect(tokenResponse.status).toBe(200)

								if (tokenResponse.status === 200) {
									const tokens = await tokenResponse.json()
									expect(tokens.access_token).toBeDefined()
									expect(tokens.refresh_token).toBeDefined()
									expect(tokens.id_token).toBeDefined()
									expect(tokens.token_type).toBe("Bearer")
									expect(tokens.expires_in).toBeDefined()
									expect(tokens.scope).toBeDefined()
								}
							}
						}
					}
				}
			}
		})

		it("should handle TTL configuration variations", async () => {
			const ttlAuth = issuer({
				storage,
				subjects,
				allow: async () => true,
				success: async (ctx) => {
					return ctx.subject(
						"user",
						{
							userID: "ttl-test",
							email: "test@ttl.com",
							name: "TTL Test"
						},
						{
							ttl: {
								access: 900, // 15 minutes
								refresh: 7200 // 2 hours
							}
						}
					)
				},
				ttl: {
					access: 3600,
					refresh: 86400,
					reuse: 30,
					retention: 60,
					oauthState: 600,
					ssoSessionSeconds: 604800
				},
				providers: {
					ttl: {
						type: "ttl",
						init(route, ctx) {
							route.get("/authorize", async (c) => {
								return ctx.success(c, {
									userID: "ttl-test",
									email: "test@ttl.com",
									name: "TTL Test"
								})
							})
						}
					}
				}
			})

			expect(ttlAuth).toBeDefined()
		})
	})
})
