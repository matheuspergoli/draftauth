/**
 * Authorization allow checks tests
 */
import { describe, expect, it } from "vitest"
import { defaultAllowCheck } from "../src/allow"

describe("Allow Functions", () => {
	describe("defaultAllowCheck", () => {
		const createRequest = (url: string, headers: Record<string, string> = {}) => {
			return new Request(url, { headers })
		}

		it("should allow localhost URLs", async () => {
			const request = createRequest("https://example.com/auth")

			const localhostCases = [
				"http://localhost:3000/callback",
				"https://localhost:8080/callback",
				"http://127.0.0.1:3000/callback"
			]

			for (const redirectURI of localhostCases) {
				const result = await defaultAllowCheck(
					{
						clientID: "test-client",
						redirectURI
					},
					request
				)

				expect(result).toBe(true)
			}
		})

		it("should allow same domain redirects", async () => {
			const request = createRequest("https://myapp.com/auth")

			const result = await defaultAllowCheck(
				{
					clientID: "web-app",
					redirectURI: "https://auth.myapp.com/callback"
				},
				request
			)

			expect(result).toBe(true)
		})

		it("should reject different domain redirects", async () => {
			const request = createRequest("https://myapp.com/auth")

			const result = await defaultAllowCheck(
				{
					clientID: "malicious-app",
					redirectURI: "https://evil.com/callback"
				},
				request
			)

			expect(result).toBe(false)
		})

		it("should handle forwarded host headers", async () => {
			const request = createRequest("http://localhost:3000/auth", {
				"x-forwarded-host": "myapp.com"
			})

			const result = await defaultAllowCheck(
				{
					clientID: "web-app",
					redirectURI: "https://auth.myapp.com/callback"
				},
				request
			)

			expect(result).toBe(true)
		})

		it("should reject invalid redirect URIs", async () => {
			const request = createRequest("https://example.com/auth")

			const invalidCases = [
				"invalid-url",
				"",
				"javascript:alert('xss')",
				"data:text/html,<script>alert('xss')</script>"
			]

			for (const redirectURI of invalidCases) {
				const result = await defaultAllowCheck(
					{
						clientID: "test-client",
						redirectURI
					},
					request
				)

				expect(result).toBe(false)
			}
		})

		it("should handle malformed request URLs", async () => {
			// Create request with invalid URL structure
			const request = {
				url: "invalid-url",
				headers: {
					get: () => null
				}
			} as unknown as Request

			const result = await defaultAllowCheck(
				{
					clientID: "test-client",
					redirectURI: "https://test.com/callback"
				},
				request
			)

			expect(result).toBe(false)
		})
	})
})
