import type { Client } from "@libsql/client"
import { type StorageAdapter, joinKey, splitKey } from "./storage"

/**
 * Turso/LibSQL storage adapter for Draft Auth with automatic expiration cleanup.
 * Provides persistent storage using Turso's edge database with built-in TTL support.
 *
 * ## Features
 *
 * - **Edge database**: Fast global access through Turso's distributed architecture
 * - **Automatic expiration**: Built-in cleanup of expired entries
 * - **ACID transactions**: Reliable data consistency
 * - **Efficient scanning**: Optimized prefix-based queries
 *
 * @example
 * ```ts
 * import { createClient } from "@libsql/client"
 * import { TursoStorage } from "@draftauth/core/storage/turso"
 *
 * const client = createClient({
 *   url: "libsql://your-database.turso.io",
 *   authToken: "your-auth-token"
 * })
 *
 * const storage = TursoStorage(client)
 *
 * export default issuer({
 *   storage,
 *   // ...
 * })
 * ```
 */

/**
 * Database row structure for the key-value storage table.
 */
interface StorageRow {
	readonly key: string
	readonly value: string
	readonly expiry: number | null
}

/**
 * Creates a Turso storage adapter using the provided LibSQL client.
 * Automatically initializes the required database table and implements
 * the StorageAdapter interface with efficient SQL operations.
 *
 * @param client - Configured LibSQL client for database operations
 * @returns Storage adapter implementing the StorageAdapter interface
 *
 * @example
 * ```ts
 * import { createClient } from "@libsql/client"
 *
 * const client = createClient({
 *   url: process.env.TURSO_DATABASE_URL,
 *   authToken: process.env.TURSO_AUTH_TOKEN
 * })
 *
 * const storage = TursoStorage(client)
 *
 * // Now ready to use with Draft Auth
 * const app = issuer({ storage, ... })
 * ```
 */
export const TursoStorage = (client: Client): StorageAdapter => {
	const TABLE_NAME = "__draftauth__kv_storage"

	// Initialize the storage table with optimized schema
	client.execute(`
		CREATE TABLE IF NOT EXISTS ${TABLE_NAME} (
			key TEXT PRIMARY KEY, 
			value TEXT NOT NULL, 
			expiry INTEGER
		)
	`)

	// Create index for efficient prefix scanning
	client.execute(`
		CREATE INDEX IF NOT EXISTS idx_${TABLE_NAME}_key_prefix 
		ON ${TABLE_NAME} (key)
	`)

	// Create index for efficient expiry-based cleanup
	client.execute(`
		CREATE INDEX IF NOT EXISTS idx_${TABLE_NAME}_expiry 
		ON ${TABLE_NAME} (expiry) 
		WHERE expiry IS NOT NULL
	`)

	return {
		async get(key: string[]): Promise<Record<string, unknown> | undefined> {
			const joinedKey = joinKey(key)

			const { rows } = await client.execute({
				sql: `SELECT value, expiry FROM ${TABLE_NAME} WHERE key = ?`,
				args: [joinedKey]
			})

			const row = rows[0] as StorageRow | undefined
			if (!row) return undefined

			// Check and handle expiration
			if (row.expiry && row.expiry < Date.now()) {
				// Clean up expired entry asynchronously
				await client.execute({
					sql: `DELETE FROM ${TABLE_NAME} WHERE key = ?`,
					args: [joinedKey]
				})
				return undefined
			}

			try {
				return JSON.parse(row.value) as Record<string, unknown>
			} catch (error) {
				console.error("Failed to parse stored value:", error)
				return undefined
			}
		},

		async set(key: string[], value: unknown, expiry?: Date): Promise<void> {
			const joinedKey = joinKey(key)
			const expiryTimestamp = expiry?.getTime() ?? null

			try {
				const serializedValue = JSON.stringify(value)
				await client.execute({
					sql: `INSERT OR REPLACE INTO ${TABLE_NAME} (key, value, expiry) VALUES (?, ?, ?)`,
					args: [joinedKey, serializedValue, expiryTimestamp]
				})
			} catch (error) {
				console.error("Failed to store value:", error)
				throw new Error("Storage operation failed")
			}
		},

		async remove(key: string[]): Promise<void> {
			const joinedKey = joinKey(key)

			await client.execute({
				sql: `DELETE FROM ${TABLE_NAME} WHERE key = ?`,
				args: [joinedKey]
			})
		},

		async *scan(
			prefix: string[]
		): AsyncGenerator<readonly [string[], Record<string, unknown>], void, unknown> {
			const joinedPrefix = joinKey(prefix)
			const now = Date.now()

			const { rows } = await client.execute({
				sql: `
					SELECT key, value, expiry 
					FROM ${TABLE_NAME} 
					WHERE key LIKE ? 
					AND (expiry IS NULL OR expiry >= ?)
					ORDER BY key
				`,
				args: [`${joinedPrefix}%`, now]
			})

			for (const row of rows as unknown as StorageRow[]) {
				try {
					const parsedValue = JSON.parse(row.value) as Record<string, unknown>
					yield [splitKey(row.key), parsedValue] as const
				} catch (error) {
					console.error("Failed to parse value during scan:", error)
					// Skip malformed entries rather than failing the entire scan
				}
			}

			// Opportunistic cleanup of expired entries (non-blocking)
			client
				.execute({
					sql: `DELETE FROM ${TABLE_NAME} WHERE expiry IS NOT NULL AND expiry < ?`,
					args: [now]
				})
				.catch((error) => {
					console.warn("Background cleanup failed:", error)
				})
		}
	}
}
