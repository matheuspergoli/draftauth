import type { Client } from "@libsql/client"
import { type StorageAdapter, joinKey, splitKey } from "@openauthjs/openauth/storage/storage"

export const TursoStorage = (client: Client): StorageAdapter => {
	const TABLE_NAME = "__draftauth__kv_storage"

	client.execute(`
		CREATE TABLE IF NOT EXISTS ${TABLE_NAME} (
			key TEXT PRIMARY KEY, 
			value TEXT, 
			expiry INTEGER
		)
	`)

	return {
		async get(key: string[]) {
			const joined = joinKey(key)
			const { rows } = await client.execute({
				sql: `SELECT value, expiry FROM ${TABLE_NAME} WHERE key = ?`,
				args: [joined]
			})
			const row = rows[0] as { value: string; expiry: number } | undefined
			if (row?.expiry && row.expiry < Date.now()) {
				await client.execute({
					sql: `DELETE FROM ${TABLE_NAME} WHERE key = ?`,
					args: [joined]
				})
				return undefined
			}
			return row ? (JSON.parse(row.value) as Record<string, unknown>) : undefined
		},
		async set(key: string[], value: unknown, expiry?: Date) {
			const joined = joinKey(key)
			const expiryTimestamp = expiry ? expiry.getTime() : null

			await client.execute({
				sql: `INSERT OR REPLACE INTO ${TABLE_NAME} (key, value, expiry) VALUES (?, ?, ?)`,
				args: [joined, JSON.stringify(value), expiryTimestamp]
			})
		},
		async remove(key: string[]) {
			const joined = joinKey(key)

			await client.execute({
				sql: `DELETE FROM ${TABLE_NAME} WHERE key = ?`,
				args: [joined]
			})
		},
		async *scan(prefix: string[]) {
			const joined = joinKey(prefix)

			const { rows } = await client.execute({
				sql: `SELECT key, value, expiry FROM ${TABLE_NAME} WHERE key LIKE ?`,
				args: [`${joined}%`]
			})

			for (const row of rows as unknown as {
				key: string
				value: string
				expiry: number
			}[]) {
				if (row.expiry && row.expiry < Date.now()) {
					continue
				}
				yield [splitKey(row.key), JSON.parse(row.value)]
			}
		}
	}
}
