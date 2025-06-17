import {
	type JWTHeaderParameters,
	type JWTPayload,
	type JWTVerifyResult,
	SignJWT,
	jwtVerify
} from "jose"
import type { KeyLike } from "./keys"

/**
 * JWT utilities for creating and verifying JSON Web Tokens.
 * Provides simplified interfaces for common JWT operations used in OAuth flows.
 */

/**
 * JWT creation and verification utilities.
 */
export const jwt = {
	/**
	 * Creates a signed JWT with the specified payload and signing key.
	 * Sets standard JWT headers including algorithm, type, and key ID.
	 *
	 * @param payload - The JWT payload containing claims
	 * @param algorithm - The signing algorithm to use (e.g., 'ES256', 'RS256')
	 * @param privateKey - The private key for signing the JWT
	 * @param keyId - Optional key identifier for the JWT header
	 * @returns Promise resolving to the signed JWT string
	 *
	 * @example
	 * ```ts
	 * const token = await jwt.create(
	 *   {
	 *     sub: 'user123',
	 *     exp: Math.floor(Date.now() / 1000) + 3600
	 *   },
	 *   'ES256',
	 *   signingKey.private,
	 *   signingKey.id
	 * )
	 * ```
	 */
	create: (
		payload: JWTPayload,
		algorithm: string,
		privateKey: KeyLike,
		keyId?: string
	): Promise<string> => {
		const header: JWTHeaderParameters = {
			alg: algorithm,
			typ: "JWT"
		}

		if (keyId) {
			header.kid = keyId
		}

		return new SignJWT(payload).setProtectedHeader(header).sign(privateKey)
	},

	/**
	 * Verifies a JWT signature and returns the decoded payload.
	 * Validates the token signature against the provided public key.
	 * Only allows secure algorithms (ES256, RS256) by default to prevent algorithm confusion attacks.
	 *
	 * @template T - Expected shape of the JWT payload
	 * @param token - The JWT string to verify
	 * @param publicKey - The public key for signature verification
	 * @param options - Optional configuration including allowed algorithms
	 * @returns Promise resolving to JWT verification result with typed payload
	 *
	 * @example
	 * ```ts
	 * interface TokenPayload {
	 *   sub: string
	 *   exp: number
	 *   scopes: string[]
	 * }
	 *
	 * const result = await jwt.verify<TokenPayload>(token, verificationKey.public)
	 * // With custom algorithms:
	 * const result = await jwt.verify<TokenPayload>(token, key, { algorithms: ['RS256'] })
	 * ```
	 *
	 * @throws {JWTExpired} When the token has expired
	 * @throws {JWTInvalid} When the token signature is invalid
	 */
	verify: <T extends JWTPayload = JWTPayload>(
		token: string,
		publicKey: KeyLike,
		options?: { algorithms?: string[] }
	): Promise<JWTVerifyResult<T>> => {
		const allowedAlgorithms = options?.algorithms || ["ES256", "RS256"]

		return jwtVerify<T>(token, publicKey, {
			algorithms: allowedAlgorithms
		})
	}
} as const
