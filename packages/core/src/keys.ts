import {
	type JWK,
	exportJWK,
	exportPKCS8,
	exportSPKI,
	generateKeyPair,
	importPKCS8,
	importSPKI
} from "jose"
import { Storage, type StorageAdapter } from "./storage/storage"

/**
 * Cryptographic key management for JWT signing and encryption operations.
 * Handles automatic key generation, rotation, and storage for OAuth 2.0 operations.
 */

/** Elliptic Curve algorithm used for JWT signing operations */
const signingAlg = "ES256"

/** RSA algorithm used for token encryption operations */
const encryptionAlg = "RSA-OAEP-512"

/**
 * Generic key-like object that can be used for cryptographic operations.
 * Represents either public or private keys from the Web Crypto API.
 */
export type KeyLike = { type: string }

/**
 * Serialized key pair format for persistent storage.
 * Contains PEM-encoded keys and metadata for reconstruction.
 */
interface SerializedKeyPair {
	/** Unique identifier for the key pair */
	readonly id: string
	/** PEM-encoded public key */
	readonly publicKey: string
	/** PEM-encoded private key */
	readonly privateKey: string
	/** Timestamp when the key was created */
	readonly created: number
	/** Algorithm used for this key pair */
	readonly alg: string
	/** Optional expiration timestamp */
	readonly expired?: number
}

/**
 * Runtime key pair with loaded cryptographic keys and metadata.
 * Ready for immediate use in signing and encryption operations.
 */
export interface KeyPair {
	/** Unique identifier for the key pair */
	readonly id: string
	/** Algorithm used for this key pair */
	readonly alg: string
	/** Loaded public key for verification/encryption */
	readonly public: KeyLike
	/** Loaded private key for signing/decryption */
	readonly private: KeyLike
	/** Date when the key was created */
	readonly created: Date
	/** Optional expiration date */
	readonly expired?: Date
	/** JSON Web Key representation for JWKS endpoints */
	readonly jwk: JWK
}

/**
 * Loads or generates signing keys for JWT operations.
 * Returns existing valid keys, or generates new ones if none are available.
 * Keys are automatically sorted by creation date (newest first).
 *
 * @param storage - Storage adapter for persistent key storage
 * @returns Promise resolving to array of available signing key pairs
 *
 * @example
 * ```ts
 * const keys = await signingKeys(storage)
 * const currentKey = keys[0] // Most recent key
 *
 * // Use for JWT signing
 * const jwt = await new SignJWT(payload)
 *   .setProtectedHeader({ alg: currentKey.alg, kid: currentKey.id })
 *   .sign(currentKey.private)
 * ```
 */
export const signingKeys = async (storage: StorageAdapter): Promise<KeyPair[]> => {
	const results: KeyPair[] = []
	const scanner = Storage.scan<SerializedKeyPair>(storage, ["signing:key"])

	for await (const [, value] of scanner) {
		try {
			const publicKey = await importSPKI(value.publicKey, value.alg, {
				extractable: true
			})
			const privateKey = await importPKCS8(value.privateKey, value.alg)
			const jwk = await exportJWK(publicKey)
			jwk.kid = value.id
			jwk.use = "sig"

			results.push({
				id: value.id,
				alg: signingAlg,
				created: new Date(value.created),
				expired: value.expired ? new Date(value.expired) : undefined,
				public: publicKey,
				private: privateKey,
				jwk
			})
		} catch {}
	}

	// Sort by creation date (newest first)
	results.sort((a, b) => b.created.getTime() - a.created.getTime())

	// Return existing keys if any are still valid
	if (results.filter((item) => !item.expired).length) {
		return results
	}

	// Generate new signing key if none available
	const key = await generateKeyPair(signingAlg, {
		extractable: true
	})

	const serialized: SerializedKeyPair = {
		id: crypto.randomUUID(),
		publicKey: await exportSPKI(key.publicKey),
		privateKey: await exportPKCS8(key.privateKey),
		created: Date.now(),
		alg: signingAlg
	}

	await Storage.set(storage, ["signing:key", serialized.id], serialized)
	return signingKeys(storage)
}

/**
 * Loads or generates encryption keys for token encryption operations.
 * Returns existing valid keys, or generates new ones if none are available.
 * Keys are automatically sorted by creation date (newest first).
 *
 * @param storage - Storage adapter for persistent key storage
 * @returns Promise resolving to array of available encryption key pairs
 *
 * @example
 * ```ts
 * const keys = await encryptionKeys(storage)
 * const currentKey = keys[0] // Most recent key
 *
 * // Use for token encryption
 * const encrypted = await new EncryptJWT(payload)
 *   .setProtectedHeader({ alg: 'RSA-OAEP-512', enc: 'A256GCM' })
 *   .encrypt(currentKey.public)
 * ```
 */
export const encryptionKeys = async (storage: StorageAdapter): Promise<KeyPair[]> => {
	const results: KeyPair[] = []
	const scanner = Storage.scan<SerializedKeyPair>(storage, ["encryption:key"])

	for await (const [, value] of scanner) {
		try {
			const publicKey = await importSPKI(value.publicKey, value.alg, {
				extractable: true
			})
			const privateKey = await importPKCS8(value.privateKey, value.alg)
			const jwk = await exportJWK(publicKey)
			jwk.kid = value.id

			results.push({
				id: value.id,
				alg: encryptionAlg,
				created: new Date(value.created),
				expired: value.expired ? new Date(value.expired) : undefined,
				public: publicKey,
				private: privateKey,
				jwk
			})
		} catch {}
	}

	// Sort by creation date (newest first)
	results.sort((a, b) => b.created.getTime() - a.created.getTime())

	// Return existing keys if any are still valid
	if (results.filter((item) => !item.expired).length) {
		return results
	}

	// Generate new encryption key if none available
	const key = await generateKeyPair(encryptionAlg, {
		extractable: true
	})

	const serialized: SerializedKeyPair = {
		id: crypto.randomUUID(),
		publicKey: await exportSPKI(key.publicKey),
		privateKey: await exportPKCS8(key.privateKey),
		created: Date.now(),
		alg: encryptionAlg
	}

	await Storage.set(storage, ["encryption:key", serialized.id], serialized)
	return encryptionKeys(storage)
}
