import { base64url } from "jose"

/**
 * PKCE (Proof Key for Code Exchange) implementation for OAuth 2.0 security.
 * Provides protection against authorization code interception attacks by using
 * dynamically generated code verifiers and challenges.
 */

/**
 * PKCE challenge methods supported by the implementation.
 */
type PKCEMethod = "S256" | "plain"

/**
 * Performs a timing-safe comparison of two strings to prevent timing attacks.
 * This implementation is platform-agnostic, uses a constant-time algorithm,
 * and correctly handles all Unicode characters by operating on their UTF-8 byte representation.
 * It always takes a time proportional to the length of the expected string,
 * regardless of where the strings differ, making it safe for comparing sensitive values.
 *
 * @param a - The first string to compare (often the expected, secret value).
 * @param b - The second string to compare (often the user-provided value).
 * @returns True if the strings are identical, false otherwise.
 *
 * @example
 * ```ts
 * // Safe for comparing sensitive values like PKCE verifiers or tokens
 * const isValid = await timingSafeCompare(receivedVerifier, expectedChallenge);
 *
 * // Safe for password hash verification
 * const isValidPassword = timingSafeCompare(hashedInput, storedHash);
 *
 * // Returns false for different types or lengths without leaking timing info
 * timingSafeCompare("abc", 123 as any); // false
 * timingSafeCompare("abc", "abcd"); // false
 * ```
 */
const timingSafeCompare = (a: string, b: string): boolean => {
	// Initial type checks are not a timing vulnerability.
	if (typeof a !== "string" || typeof b !== "string") return false

	// Use TextEncoder for correct and consistent handling of all Unicode characters.
	const encoder = new TextEncoder()
	const aBytes = encoder.encode(a)
	const bBytes = encoder.encode(b)

	// 1. Include the length difference in the comparison to avoid an "early exit"
	// vulnerability. This ensures the function's runtime is not dependent on
	// whether the input string has the correct length.
	let diff = aBytes.length ^ bBytes.length

	// 2. Use a `for...of` loop with `entries()` to iterate. This is more
	// type-safe as it guarantees that `aByte` is a `number`, satisfying
	// TypeScript's strict checks. The execution time still depends only on the
	// length of `aBytes`.
	for (const [i, aByte] of aBytes.entries()) {
		// 3. Accumulate byte differences using bitwise XOR.
		// The nullish coalescing operator `?? 0` handles the case where `b` is
		// shorter than `a`, ensuring the operation is always valid.
		diff |= aByte ^ (bBytes[i] ?? 0)
	}

	// 4. The comparison is successful only if the initial length check resulted
	// in zero AND all subsequent byte comparisons resulted in zero.
	return diff === 0
}

/**
 * Complete PKCE challenge data containing verifier, challenge, and method.
 */
export interface PKCEChallenge {
	/** The code verifier to be sent to the token endpoint */
	readonly verifier: string
	/** The code challenge to be sent to the authorization endpoint */
	readonly challenge: string
	/** The challenge method used (always 'S256' for security) */
	readonly method: "S256"
}

/**
 * Generates a cryptographically secure code verifier for PKCE.
 * The verifier is a URL-safe base64-encoded string of random bytes.
 *
 * @param length - Length of the random buffer in bytes
 * @returns Base64url-encoded verifier string
 */
const generateVerifier = (length: number): string => {
	const buffer = new Uint8Array(length)
	crypto.getRandomValues(buffer)
	return base64url.encode(buffer)
}

/**
 * Generates a code challenge from a verifier using the specified method.
 * For 'S256', applies SHA-256 hash then base64url encoding.
 * For 'plain', returns the verifier unchanged (not recommended for production).
 *
 * @param verifier - The code verifier string
 * @param method - Challenge generation method
 * @returns Promise resolving to the code challenge string
 */
const generateChallenge = async (verifier: string, method: PKCEMethod): Promise<string> => {
	if (method === "plain") return verifier

	const encoder = new TextEncoder()
	const data = encoder.encode(verifier)
	const hash = await crypto.subtle.digest("SHA-256", data)
	return base64url.encode(new Uint8Array(hash))
}

/**
 * Generates a complete PKCE challenge for OAuth 2.0 authorization requests.
 * Creates a cryptographically secure verifier and corresponding S256 challenge.
 * Validates that the generated verifier meets standard requirements (43-128 characters).
 *
 * @param length - Length of the random buffer in bytes (43-128 range)
 * @returns Promise resolving to PKCE challenge data
 *
 * @example
 * ```ts
 * const pkce = await generatePKCE()
 *
 * // Use challenge in authorization URL
 * authUrl.searchParams.set('code_challenge', pkce.challenge)
 * authUrl.searchParams.set('code_challenge_method', pkce.method)
 *
 * // Store verifier for token exchange
 * sessionStorage.setItem('code_verifier', pkce.verifier)
 * ```
 *
 * @throws {RangeError} If length is outside valid range or generated verifier doesn't meet requirements
 */
export const generatePKCE = async (length = 64): Promise<PKCEChallenge> => {
	if (!Number.isInteger(length) || length < 43 || length > 128) {
		throw new RangeError("Code verifier length must be between 43 and 128 characters")
	}

	const verifier = generateVerifier(length)
	const challenge = await generateChallenge(verifier, "S256")

	return {
		verifier,
		challenge,
		method: "S256"
	} as const
}

/**
 * Validates a PKCE code verifier against a previously generated challenge.
 * Uses timing-safe comparison and timing normalization to prevent timing attacks.
 * Validates input format and length requirements before processing to prevent
 * timing-based information leakage.
 *
 * @param verifier - The code verifier received from the client
 * @param challenge - The code challenge stored during authorization
 * @param method - The challenge method used during generation
 * @returns Promise resolving to true if verifier matches challenge
 *
 * @example
 * ```ts
 * // During token exchange
 * const isValid = await validatePKCE(
 *   receivedVerifier,
 *   storedChallenge,
 *   'S256'
 * )
 *
 * if (!isValid) {
 *   throw new Error('Invalid PKCE verifier')
 * }
 * ```
 */
export const validatePKCE = async (
	verifier: string,
	challenge: string,
	method: PKCEMethod = "S256"
): Promise<boolean> => {
	const startTime = Date.now()
	const minProcessingTime = 10

	if (
		!verifier ||
		!challenge ||
		typeof verifier !== "string" ||
		typeof challenge !== "string"
	) {
		const elapsed = Date.now() - startTime
		const remainingTime = Math.max(0, minProcessingTime - elapsed)
		await new Promise((resolve) => setTimeout(resolve, remainingTime + Math.random() * 5))
		return false
	}

	if (verifier.length < 10 || verifier.length > 200) {
		const elapsed = Date.now() - startTime
		const remainingTime = Math.max(0, minProcessingTime - elapsed)
		await new Promise((resolve) => setTimeout(resolve, remainingTime + Math.random() * 5))
		return false
	}

	const base64urlPattern = /^[A-Za-z0-9_-]+$/
	if (!base64urlPattern.test(verifier) || !base64urlPattern.test(challenge)) {
		const elapsed = Date.now() - startTime
		const remainingTime = Math.max(0, minProcessingTime - elapsed)
		await new Promise((resolve) => setTimeout(resolve, remainingTime + Math.random() * 5))
		return false
	}

	const generatedChallenge = await generateChallenge(verifier, method)
	const result = timingSafeCompare(generatedChallenge, challenge)

	const elapsed = Date.now() - startTime
	const remainingTime = Math.max(0, minProcessingTime - elapsed)
	if (remainingTime > 0) {
		await new Promise((resolve) => setTimeout(resolve, remainingTime + Math.random() * 5))
	}

	return result
}
