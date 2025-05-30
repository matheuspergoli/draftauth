export interface StorageAdapter {
	get(key: string[]): Promise<Record<string, unknown> | undefined>
	remove(key: string[]): Promise<void>
	set(key: string[], value: unknown, expiry?: Date): Promise<void>
	scan(prefix: string[]): AsyncIterable<[string[], unknown]>
}

const SEPERATOR = String.fromCharCode(0x1f)

export const joinKey = (key: string[]) => {
	return key.join(SEPERATOR)
}

export const splitKey = (key: string) => {
	return key.split(SEPERATOR)
}

export const Storage = {
	encode: (key: string[]) => {
		return key.map((k) => k.replaceAll(SEPERATOR, ""))
	},

	get: <T>(adapter: StorageAdapter, key: string[]) => {
		return adapter.get(Storage.encode(key)) as Promise<T | null>
	},

	set: (adapter: StorageAdapter, key: string[], value: unknown, ttl?: number) => {
		const expiry = ttl ? new Date(Date.now() + ttl * 1000) : undefined
		return adapter.set(Storage.encode(key), value, expiry)
	},

	remove: (adapter: StorageAdapter, key: string[]) => {
		return adapter.remove(Storage.encode(key))
	},

	scan: <T>(adapter: StorageAdapter, key: string[]): AsyncIterable<[string[], T]> => {
		return adapter.scan(Storage.encode(key)) as AsyncIterable<[string[], T]>
	}
}
