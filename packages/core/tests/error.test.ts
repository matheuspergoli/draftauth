/**
 * Error classes tests
 */
import { describe, expect, it } from "vitest"
import {
	InvalidAccessTokenError,
	InvalidAuthorizationCodeError,
	InvalidRefreshTokenError,
	InvalidSubjectError,
	MissingParameterError,
	MissingProviderError,
	OauthError,
	TokenRevocationError,
	UnauthorizedClientError,
	UnknownStateError,
	UnsupportedTokenTypeError
} from "../src/error"

describe("Error Classes", () => {
	describe("OauthError", () => {
		it("should create OAuth error with correct properties", () => {
			const error = new OauthError("invalid_request", "Missing client_id parameter")

			expect(error.name).toBe("OauthError")
			expect(error.error).toBe("invalid_request")
			expect(error.description).toBe("Missing client_id parameter")
			expect(error.message).toBe("invalid_request - Missing client_id parameter")
			expect(error).toBeInstanceOf(Error)
		})
	})

	describe("MissingProviderError", () => {
		it("should create missing provider error", () => {
			const error = new MissingProviderError()

			expect(error.name).toBe("MissingProviderError")
			expect(error.error).toBe("invalid_request")
			expect(error.description).toContain("provider")
			expect(error).toBeInstanceOf(OauthError)
		})
	})

	describe("MissingParameterError", () => {
		it("should create missing parameter error", () => {
			const error = new MissingParameterError("client_id")

			expect(error.name).toBe("MissingParameterError")
			expect(error.error).toBe("invalid_request")
			expect(error.parameter).toBe("client_id")
			expect(error.description).toContain("client_id")
			expect(error).toBeInstanceOf(OauthError)
		})
	})

	describe("UnauthorizedClientError", () => {
		it("should create unauthorized client error", () => {
			const error = new UnauthorizedClientError("test-client", "https://test.com/callback")

			expect(error.name).toBe("UnauthorizedClientError")
			expect(error.error).toBe("unauthorized_client")
			expect(error.clientID).toBe("test-client")
			expect(error.description).toContain("test-client")
			expect(error.description).toContain("https://test.com/callback")
			expect(error).toBeInstanceOf(OauthError)
		})
	})

	describe("UnknownStateError", () => {
		it("should create unknown state error", () => {
			const error = new UnknownStateError()

			expect(error.name).toBe("UnknownStateError")
			expect(error.message).toContain("unknown state")
			expect(error).toBeInstanceOf(Error)
		})
	})

	describe("Token Errors", () => {
		it("should create token-related errors", () => {
			const subjectError = new InvalidSubjectError()
			const refreshError = new InvalidRefreshTokenError()
			const accessError = new InvalidAccessTokenError()
			const codeError = new InvalidAuthorizationCodeError()
			const tokenTypeError = new UnsupportedTokenTypeError()

			expect(subjectError.name).toBe("InvalidSubjectError")
			expect(refreshError.name).toBe("InvalidRefreshTokenError")
			expect(accessError.name).toBe("InvalidAccessTokenError")
			expect(codeError.name).toBe("InvalidAuthorizationCodeError")
			expect(tokenTypeError.name).toBe("UnsupportedTokenTypeError")

			expect(subjectError).toBeInstanceOf(Error)
			expect(refreshError).toBeInstanceOf(Error)
			expect(accessError).toBeInstanceOf(Error)
			expect(codeError).toBeInstanceOf(Error)
			expect(tokenTypeError).toBeInstanceOf(Error)
		})

		it("should create token revocation error with custom message", () => {
			const errorWithMessage = new TokenRevocationError("Custom error")
			const errorWithoutMessage = new TokenRevocationError()

			expect(errorWithMessage.message).toBe("Custom error")
			expect(errorWithoutMessage.message).toBe("Token revocation failed")
			expect(errorWithMessage.name).toBe("TokenRevocationError")
		})
	})

	describe("Error Type Checking", () => {
		it("should support instanceof checks", () => {
			const oauthError = new MissingParameterError("test")
			const tokenError = new InvalidRefreshTokenError()

			expect(oauthError instanceof OauthError).toBe(true)
			expect(tokenError instanceof OauthError).toBe(false)
			expect(oauthError instanceof Error).toBe(true)
			expect(tokenError instanceof Error).toBe(true)
		})
	})
})
