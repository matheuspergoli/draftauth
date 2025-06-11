import { existsSync, readFileSync } from "node:fs"
import { writeFile } from "node:fs/promises"
import { type StorageAdapter, joinKey, splitKey } from "./storage"

/**
 * In-memory storage adapter for Draft Auth with optional file persistence.
 *
 * ## Usage
 *
 * ### Basic in-memory storage (development only)
 * ```ts
 * import { MemoryStorage } from "@draftauth/core/storage/memory"
 *
 * const storage = MemoryStorage()
 *
 * export default issuer({
 *   storage,
 *   // ...
 * })
 * ```
 *
 * ### With file persistence
 * ```ts
 * const storage = MemoryStorage({
 *   persist: "./data/auth-storage.json"
 * })
 * ```
 *
 * ## Important Notes
 *
 * - **Not for production**: Use proper databases in production environments
 * - **Development friendly**: Great for testing and local development
 * - **Optional persistence**: Can backup to file to survive restarts
 * - **Automatic cleanup**: Expired entries are removed automatically
 *
 * @packageDocumentation
 */

/**
 * Configuration options for the memory storage adapter.
 */
export interface MemoryStorageOptions {
	/**
	 * File path for persisting the in-memory store to disk.
	 * When specified, the store will be saved to this file on changes
	 * and loaded from it on startup if it exists.
	 *
	 * @example
	 * ```ts
	 * {
	 *   persist: "./data/auth-storage.json"
	 * }
	 * ```
	 */
	readonly persist?: string
}

/**
 * Internal store entry format containing value and optional expiration.
 */
type StoreEntry = readonly [
	string,
	{
		readonly value: Record<string, unknown>
		readonly expiry?: number
	}
]

/**
 * Creates an in-memory storage adapter with optional file persistence.
 * Uses binary search for efficient key lookups and maintains sorted order.
 *
 * @param options - Configuration options for the memory storage
 * @returns Storage adapter implementing the StorageAdapter interface
 *
 * @example
 * ```ts
 * // Development storage (data lost on restart)
 * const devStorage = MemoryStorage()
 *
 * // Persistent storage (survives restarts)
 * const persistentStorage = MemoryStorage({
 *   persist: "./auth-data.json"
 * })
 *
 * // Use with issuer
 * export default issuer({
 *   storage: persistentStorage,
 *   providers: { ... }
 * })
 * ```
 */
export const MemoryStorage = (options?: MemoryStorageOptions): StorageAdapter => {
	const store: StoreEntry[] = []

	/**
	 * Type guard to validate loaded store data structure.
	 */
	const isValidStoreData = (data: unknown): data is StoreEntry[] => {
		return (
			Array.isArray(data) &&
			data.every(
				(item) =>
					Array.isArray(item) &&
					item.length === 2 &&
					typeof item[0] === "string" &&
					typeof item[1] === "object" &&
					item[1] !== null &&
					"value" in item[1]
			)
		)
	}

	// Load persisted data on initialization
	if (options?.persist && existsSync(options.persist)) {
		try {
			const fileContent = readFileSync(options.persist, "utf8")
			const parsed = JSON.parse(fileContent)
			if (isValidStoreData(parsed)) {
				store.push(...parsed)
			}
		} catch (error) {
			console.warn("Failed to load persisted storage:", error)
		}
	}

	/**
	 * Saves the current store state to the persistence file if configured.
	 */
	const save = async (): Promise<void> => {
		if (!options?.persist) return

		try {
			const serialized = JSON.stringify(store, null, 2)
			await writeFile(options.persist, serialized, "utf8")
		} catch (error) {
			console.error("Failed to save storage to file:", error)
		}
	}

	/**
	 * Performs binary search to find a key in the sorted store.
	 * Returns both whether the key was found and the insertion index.
	 */
	const search = (key: string): { found: boolean; index: number } => {
		let left = 0
		let right = store.length - 1

		while (left <= right) {
			const mid = Math.floor((left + right) / 2)
			const midEntry = store[mid]

			if (!midEntry) {
				return { found: false, index: left }
			}

			const comparison = key.localeCompare(midEntry[0])
			if (comparison === 0) {
				return { found: true, index: mid }
			}
			if (comparison < 0) {
				right = mid - 1
			} else {
				left = mid + 1
			}
		}

		return { found: false, index: left }
	}

	return {
		async get(key: string[]): Promise<Record<string, unknown> | undefined> {
			const searchKey = joinKey(key)
			const match = search(searchKey)

			if (!match.found) return undefined

			const storeEntry = store[match.index]
			if (!storeEntry) return undefined

			const entry = storeEntry[1]

			// Check for expiration and cleanup if needed
			if (entry.expiry && Date.now() >= entry.expiry) {
				store.splice(match.index, 1)
				await save()
				return undefined
			}

			return entry.value
		},

		async set(key: string[], value: unknown, expiry?: Date): Promise<void> {
			const searchKey = joinKey(key)
			const match = search(searchKey)

			const entry: StoreEntry = [
				searchKey,
				{
					value: value as Record<string, unknown>,
					expiry: expiry?.getTime()
				}
			]

			if (match.found) {
				// Update existing entry
				store[match.index] = entry
			} else {
				// Insert new entry at correct position to maintain sort order
				store.splice(match.index, 0, entry)
			}

			await save()
		},

		async remove(key: string[]): Promise<void> {
			const searchKey = joinKey(key)
			const match = search(searchKey)

			if (match.found) {
				store.splice(match.index, 1)
				await save()
			}
		},

		async *scan(prefix: string[]) {
			const now = Date.now()
			const prefixStr = joinKey(prefix)

			for (const [key, entry] of store) {
				if (!key.startsWith(prefixStr)) continue
				if (entry.expiry && now >= entry.expiry) continue

				yield [splitKey(key), entry.value] as const
			}
		}
	}
}
