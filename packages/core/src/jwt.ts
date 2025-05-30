import { type JWTPayload, SignJWT, jwtVerify } from "jose"
import type { KeyLike } from "./keys"

export const jwt = {
	create: (payload: JWTPayload, algorithm: string, privateKey: KeyLike) => {
		return new SignJWT(payload)
			.setProtectedHeader({ alg: algorithm, typ: "JWT", kid: "sst" })
			.sign(privateKey)
	},

	verify: <T>(token: string, publicKey: KeyLike) => {
		return jwtVerify<T>(token, publicKey)
	}
}
