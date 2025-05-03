import { defineConfig } from "drizzle-kit"

import { env } from "./src/environment/env"

const configDev = defineConfig({
	schema: "./src/db/schema.ts",
	out: "./migrations",
	dialect: "sqlite",
	dbCredentials: {
		url: env.DATABASE_URL_DEV
	}
})

const configProd = defineConfig({
	schema: "./src/db/schema.ts",
	out: "./migrations",
	dialect: "turso",
	dbCredentials: {
		url: env.DATABASE_URL,
		authToken: env.DATABASE_AUTH_TOKEN
	}
})

const isProd = env.NODE_ENV === "production"

export default isProd ? configProd : configDev
