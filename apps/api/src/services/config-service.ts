import { db } from "@/db/client"
import { applications, systemConfiguration } from "@/db/schema"
import { eq, sql } from "drizzle-orm"

export const CONFIG_KEYS = {
	SYSTEM_OWNER_USER_ID: "system_owner_user_id",
	INITIAL_SETUP_COMPLETE: "initial_setup_complete",
	PRIMARY_MANAGEMENT_APP_ID: "primary_management_app_id"
} as const

export const getConfigValue = async (key: string) => {
	const result = await db.query.systemConfiguration.findFirst({
		where: eq(systemConfiguration.key, key),
		columns: { value: true }
	})

	return result?.value ?? null
}

export const setConfigValue = async (key: string, value: string) => {
	await db
		.insert(systemConfiguration)
		.values({ key, value })
		.onConflictDoUpdate({
			target: systemConfiguration.key,
			set: { value: value }
		})
}

export const isSetupComplete = async () => {
	const setupFlag = await getConfigValue(CONFIG_KEYS.INITIAL_SETUP_COMPLETE)

	if (setupFlag === "true") return true

	const appCountResult = await db
		.select({ count: sql<number>`cast(count(*) as int)` })
		.from(applications)
		.get()

	const appCount = appCountResult?.count ?? 0

	if (appCount > 0) {
		await setConfigValue(CONFIG_KEYS.INITIAL_SETUP_COMPLETE, "true")
		return true
	}

	return false
}
