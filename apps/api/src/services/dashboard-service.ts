import { db } from "@/db/client"
import { applications, roles, users } from "@/db/schema"
import { sql } from "drizzle-orm"

export const getDashboardStats = async () => {
	const [usersResult, appsResult, rolesResult] = await Promise.all([
		db
			.select({ count: sql<number>`cast(count(${users.userId}) as int)` })
			.from(users)
			.get(),
		db
			.select({ count: sql<number>`cast(count(${applications.appId}) as int)` })
			.from(applications)
			.get(),
		db
			.select({ count: sql<number>`cast(count(${roles.roleId}) as int)` })
			.from(roles)
			.get()
	])

	return {
		totalUsers: usersResult?.count ?? 0,
		rolesDefined: rolesResult?.count ?? 0,
		activeApplications: appsResult?.count ?? 0
	}
}
