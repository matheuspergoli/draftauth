/**
 * Storage abstraction layer for Draft Auth persistence operations.
 * Provides a unified interface for different storage backends with key encoding,
 * TTL support, and type-safe operations.
 */

/**
 * Abstract storage adapter interface that must be implemented by all storage backends.
 * Defines the core operations needed for OAuth data persistence.
 */
export interface StorageAdapter {
	/**
	 * Retrieves a value by its key path.
	 *
	 * @param key - Array of key segments forming the storage path
	 * @returns Promise resolving to the stored value or undefined if not found
	 */
	get(key: string[]): Promise<Record<string, unknown> | undefined>

	/**
	 * Removes a value by its key path.
	 *
	 * @param key - Array of key segments forming the storage path
	 * @returns Promise that resolves when removal is complete
	 */
	remove(key: string[]): Promise<void>

	/**
	 * Stores a value with an optional expiration date.
	 *
	 * @param key - Array of key segments forming the storage path
	 * @param value - The value to store
	 * @param expiry - Optional expiration date for automatic cleanup
	 * @returns Promise that resolves when storage is complete
	 */
	set(key: string[], value: unknown, expiry?: Date): Promise<void>

	/**
	 * Scans for keys matching a prefix pattern.
	 *
	 * @param prefix - Array of key segments to use as prefix filter
	 * @returns Async iterable of key-value pairs matching the prefix
	 */
	scan(prefix: string[]): AsyncIterable<readonly [string[], unknown]>
}

/**
 * ASCII unit separator character used to join key segments.
 * Using a control character ensures it won't conflict with user data.
 */
const SEPARATOR = String.fromCharCode(0x1f)

/**
 * Joins an array of key segments into a single string using the separator.
 *
 * @param key - Array of key segments to join
 * @returns Single string representing the full key path
 *
 * @example
 * ```ts
 * joinKey(['user', 'session', '123'])
 * // Returns: "user\x1fsession\x1f123"
 * ```
 */
export const joinKey = (key: string[]): string => {
	return key.join(SEPARATOR)
}

/**
 * Splits a joined key string back into its component segments.
 *
 * @param key - Joined key string to split
 * @returns Array of individual key segments
 *
 * @example
 * ```ts
 * splitKey("user\x1fsession\x1f123")
 * // Returns: ['user', 'session', '123']
 * ```
 */
export const splitKey = (key: string): string[] => {
	return key.split(SEPARATOR)
}

/**
 * High-level storage operations with key encoding and type safety.
 * Provides a convenient interface over storage adapters with additional features
 * like TTL conversion and key sanitization.
 */
export const Storage = {
	/**
	 * Encodes key segments by removing any separator characters to prevent conflicts.
	 * Ensures storage keys don't contain characters that could break key parsing.
	 *
	 * @param key - Array of key segments to encode
	 * @returns Array of sanitized key segments
	 *
	 * @example
	 * ```ts
	 * Storage.encode(['user', 'data\x1fwith\x1fseparators'])
	 * // Returns: ['user', 'datawithseparators']
	 * ```
	 */
	encode: (key: string[]): string[] => {
		return key.map((segment) => segment.replaceAll(SEPARATOR, ""))
	},

	/**
	 * Retrieves a typed value from storage.
	 *
	 * @template T - Expected type of the stored value
	 * @param adapter - Storage adapter to use
	 * @param key - Array of key segments identifying the value
	 * @returns Promise resolving to the typed value or null if not found
	 *
	 * @example
	 * ```ts
	 * interface UserSession {
	 *   userId: string
	 *   expiresAt: number
	 * }
	 *
	 * const session = await Storage.get<UserSession>(adapter, ['sessions', sessionId])
	 * if (session) {
	 *   // Fully typed: session.userId
	 * }
	 * ```
	 */
	get: <T = Record<string, unknown>>(
		adapter: StorageAdapter,
		key: string[]
	): Promise<T | null> => {
		return adapter.get(Storage.encode(key)) as Promise<T | null>
	},

	/**
	 * Stores a value with optional time-to-live in seconds.
	 *
	 * @param adapter - Storage adapter to use
	 * @param key - Array of key segments identifying where to store
	 * @param value - The value to store
	 * @param ttlSeconds - Optional TTL in seconds for automatic expiration
	 * @returns Promise that resolves when storage is complete
	 *
	 * @example
	 * ```ts
	 * // Store with 1 hour TTL
	 * await Storage.set(adapter, ['sessions', sessionId], sessionData, 3600)
	 *
	 * // Store permanently
	 * await Storage.set(adapter, ['users', userId], userData)
	 * ```
	 */
	set: (
		adapter: StorageAdapter,
		key: string[],
		value: unknown,
		ttlSeconds?: number
	): Promise<void> => {
		const expiry = ttlSeconds ? new Date(Date.now() + ttlSeconds * 1000) : undefined
		return adapter.set(Storage.encode(key), value, expiry)
	},

	/**
	 * Removes a value from storage.
	 *
	 * @param adapter - Storage adapter to use
	 * @param key - Array of key segments identifying the value to remove
	 * @returns Promise that resolves when removal is complete
	 *
	 * @example
	 * ```ts
	 * await Storage.remove(adapter, ['sessions', expiredSessionId])
	 * ```
	 */
	remove: (adapter: StorageAdapter, key: string[]): Promise<void> => {
		return adapter.remove(Storage.encode(key))
	},

	/**
	 * Scans for entries matching a key prefix with type safety.
	 *
	 * @template T - Expected type of the stored values
	 * @param adapter - Storage adapter to use
	 * @param prefix - Array of key segments to use as prefix filter
	 * @returns Async iterable of typed key-value pairs
	 *
	 * @example
	 * ```ts
	 * // Find all user sessions
	 * for await (const [key, session] of Storage.scan<UserSession>(adapter, ['sessions'])) {
	 *   // Session: `${key.join('/')} expires at ${session.expiresAt}`
	 * }
	 * ```
	 */
	scan: <T = Record<string, unknown>>(
		adapter: StorageAdapter,
		prefix: string[]
	): AsyncIterable<readonly [string[], T]> => {
		return adapter.scan(Storage.encode(prefix)) as AsyncIterable<readonly [string[], T]>
	}
} as const
