import { env } from "@/environment/env"
import { type Client, createClient } from "@libsql/client"
import { drizzle } from "drizzle-orm/libsql"

import * as schema from "./schema"

const globalForDb = globalThis as unknown as {
	client: Client | undefined
}

const isProd = env.NODE_ENV === "production"

const config = {
	url: isProd ? env.DATABASE_URL : env.DATABASE_URL_DEV,
	authToken: isProd ? env.DATABASE_AUTH_TOKEN : undefined
} satisfies { url: string; authToken?: string }

export const dbClient = globalForDb.client ?? createClient(config)

if (isProd) globalForDb.client = dbClient

export const db = drizzle(dbClient, {
	schema
})
