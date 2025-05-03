import { createEnv } from "@t3-oss/env-core"
import { z } from "zod"

export const env = createEnv({
	client: {
		VITE_BACKEND_URL: z.string(),
		VITE_APPLICATION_ID: z.string()
	},
	clientPrefix: "VITE_",
	runtimeEnv: import.meta.env,
	emptyStringAsUndefined: true
})
