import { type Client, type Config, createClient } from "@libsql/client"
import { drizzle } from "drizzle-orm/libsql"

import { env } from "@/environment/env"
import * as schema from "./schema"

const globalForDb = globalThis as unknown as {
	client: Client | undefined
}

const getDbConfig = (): Config => {
	if (env.NODE_ENV === "production") {
		return {
			url: env.DATABASE_URL,
			authToken: env.DATABASE_AUTH_TOKEN
		}
	}

	return {
		url: env.DATABASE_URL_DEV
	}
}

const config = getDbConfig()

export const dbClient = globalForDb.client ?? createClient(config)

if (env.NODE_ENV === "production") {
	globalForDb.client = dbClient
}

export const db = drizzle(dbClient, {
	schema
})
