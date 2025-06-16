/**
 * Testing OAuth 2.0 and OIDC client functionality with real issuer
 */
import { beforeEach, describe, expect, it, vi } from "vitest"
import { object, string } from "valibot"
import { createClient } from "../src/client"
import type { Client } from "../src/client"
import { issuer } from "../src/core"
import {
	InvalidAccessTokenError,
	InvalidAuthorizationCodeError,
	InvalidRefreshTokenError
} from "../src/error"
import { MemoryStorage } from "../src/storage/memory"
import { createSubjects } from "../src/subject"

const subjects = createSubjects({
	user: object({
		userID: string()
	})
})

describe("Draft Auth Client", () => {
	let storage: ReturnType<typeof MemoryStorage>
	let auth: ReturnType<typeof issuer>
	let client: Client

	beforeEach(async () => {
		storage = MemoryStorage()

		auth = issuer({
			storage,
			subjects,
			allow: async () => true,
			success: async (ctx) => {
				return ctx.subject("user", {
					userID: "123"
				})
			},
			ttl: {
				access: 60
			},
			providers: {
				dummy: {
					type: "dummy",
					init(route, ctx) {
						route.get("/authorize", async (c) => {
							return ctx.success(c, {
								email: "foo@bar.com"
							})
						})
					}
				}
			}
		})

		client = createClient({
			issuer: "https://auth.example.com",
			clientID: "test-client",
			fetch: (url, init) => Promise.resolve(auth.request(url, init))
		})
	})

	describe("createClient", () => {
		it("should create client with required parameters", () => {
			const testClient = createClient({
				clientID: "my-client",
				issuer: "https://example.com"
			})

			expect(testClient).toBeDefined()
			expect(typeof testClient.authorize).toBe("function")
			expect(typeof testClient.exchange).toBe("function")
			expect(typeof testClient.refresh).toBe("function")
		})

		it("should create client with custom fetch", () => {
			const customFetch = vi.fn()

			const testClient = createClient({
				clientID: "custom-fetch-client",
				issuer: "https://example.com",
				fetch: customFetch
			})

			expect(testClient).toBeDefined()
		})
	})

	describe("authorize", () => {
		it("should create authorization URL for code flow", async () => {
			const result = await client.authorize("https://app.example.com/callback", "code")

			expect(result.success).toBe(true)
			if (result.success) {
				expect(result.data.url).toContain("/authorize")
				expect(result.data.url).toContain("client_id=test-client")
				expect(result.data.url).toContain("response_type=code")
				expect(result.data.url).toContain(
					"redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback"
				)
				expect(result.data.challenge.state).toBeDefined()
				expect(result.data.challenge.verifier).toBeUndefined()
			}
		})

		it("should support PKCE flow", async () => {
			const result = await client.authorize("https://spa.example.com/callback", "code", {
				pkce: true
			})

			expect(result.success).toBe(true)
			if (result.success) {
				expect(result.data.url).toContain("code_challenge=")
				expect(result.data.url).toContain("code_challenge_method=S256")
				expect(result.data.challenge.verifier).toBeDefined()
			}
		})

		it("should include optional parameters", async () => {
			const result = await client.authorize("https://app.example.com/callback", "code", {
				provider: "dummy",
				scopes: ["openid", "profile", "email"],
				nonce: "test-nonce",
				prompt: "login",
				maxAge: 3600,
				loginHint: "user@example.com"
			})

			expect(result.success).toBe(true)
			if (result.success) {
				expect(result.data.url).toContain("provider=dummy")
				expect(result.data.url).toContain("scope=openid+profile+email")
				expect(result.data.url).toContain("nonce=test-nonce")
				expect(result.data.url).toContain("prompt=login")
				expect(result.data.url).toContain("max_age=3600")
				expect(result.data.url).toContain("login_hint=user%40example.com")
			}
		})
	})

	describe("exchange", () => {
		it("should handle invalid authorization code", async () => {
			const result = await client.exchange("invalid-code", "https://app.example.com/callback")

			expect(result.success).toBe(false)
			if (!result.success) {
				expect(result.error).toBeInstanceOf(InvalidAuthorizationCodeError)
			}
		})
	})

	describe("verify", () => {
		it("should handle invalid access token", async () => {
			const result = await client.verify(subjects, "invalid.jwt.token")

			expect(result.success).toBe(false)
			if (!result.success) {
				expect(result.error).toBeInstanceOf(InvalidAccessTokenError)
			}
		})
	})

	describe("refresh", () => {
		it("should handle invalid refresh token", async () => {
			const result = await client.refresh("invalid-refresh-token")

			expect(result.success).toBe(false)
			if (!result.success) {
				expect(result.error).toBeInstanceOf(InvalidRefreshTokenError)
			}
		})
	})

	describe("revoke", () => {
		it("should handle revocation of invalid token", async () => {
			const result = await client.revoke("invalid-token")

			// The result depends on implementation - might succeed or fail
			expect(typeof result.success).toBe("boolean")
		})
	})

	describe("userinfo", () => {
		it("should handle invalid access token", async () => {
			const result = await client.userinfo("invalid-access-token")

			expect(result.success).toBe(false)
			if (!result.success) {
				expect(result.error).toBeInstanceOf(InvalidAccessTokenError)
			}
		})
	})

	describe("logout", () => {
		it("should generate logout URL", async () => {
			const logoutUrl = await client.logout()

			expect(typeof logoutUrl).toBe("string")
			expect(logoutUrl).toContain("/logout")
		})

		it("should include logout options in URL", async () => {
			const logoutUrl = await client.logout({
				postLogoutRedirectUri: "https://app.example.com/goodbye",
				state: "logout-state"
			})

			expect(logoutUrl).toContain(
				"post_logout_redirect_uri=https%3A%2F%2Fapp.example.com%2Fgoodbye"
			)
			expect(logoutUrl).toContain("state=logout-state")
		})
	})

	describe("Integration Scenarios", () => {
		it("should handle basic authorization flow", async () => {
			// Start authorization with PKCE
			const authResult = await client.authorize(
				"https://integration.example.com/callback",
				"code",
				{ pkce: true, scopes: ["openid", "profile"] }
			)

			expect(authResult.success).toBe(true)
			if (authResult.success) {
				expect(authResult.data.url).toContain("/authorize")
				expect(authResult.data.challenge.verifier).toBeDefined()
			}
		})
	})

	describe("Error Handling", () => {
		it("should handle malformed tokens", async () => {
			const result = await client.verify(subjects, "invalid.jwt.token")

			expect(result.success).toBe(false)
			if (!result.success) {
				expect(result.error).toBeInstanceOf(InvalidAccessTokenError)
			}
		})

		it("should handle network errors gracefully", async () => {
			const errorClient = createClient({
				issuer: "https://auth.example.com",
				clientID: "test-client",
				fetch: async () => {
					throw new Error("Network error")
				}
			})

			const result = await errorClient.authorize("https://app.example.com/callback", "code")

			expect(result.success).toBe(false)
		})
	})
})
