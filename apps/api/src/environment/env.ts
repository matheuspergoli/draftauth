import { createEnv } from "@t3-oss/env-core"
import { z } from "zod"

export const env = createEnv({
	server: {
		FRONTEND_URL: z.string(),
		OWNER_APPLICATION_ID: z.string(),
		API_SECRET_ENCRYPTION_KEY: z.string(),
		GITHUB_CLIENT_ID: z.string(),
		GITHUB_CLIENT_SECRET: z.string(),
		GOOGLE_CLIENT_ID: z.string(),
		GOOGLE_CLIENT_SECRET: z.string(),
		DATABASE_URL: z.string(),
		DATABASE_AUTH_TOKEN: z.string(),
		DATABASE_URL_DEV: z.string().optional().default("file:./db.sqlite"),
		NODE_ENV: z.enum(["development", "production", "test"]).default("development")
	},
	runtimeEnv: process.env,
	emptyStringAsUndefined: true
})
