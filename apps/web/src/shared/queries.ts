import { env } from "@/environment/env"
import { api } from "@/libs/api"
import { queryOptions } from "@tanstack/react-query"

export const queryKeys = {
	users: () => ["users"] as const,
	currentUser: () => ["current-user"] as const,
	user: (userId: string) => ["user", userId] as const,
	currentUserStatus: () => ["current-user-status"] as const,
	userApplicationsRoles: (userId: string) => ["user-applications-roles", userId] as const,
	userApplicationsAccess: (userId: string) => ["user-applications-access", userId] as const,
	userApplicationRoles: ({ userId, appId }: { userId: string; appId: string }) => {
		return ["user-application-roles", userId, appId] as const
	},
	applicationApiKeys: (appId: string) => ["application-api-key", appId] as const,
	applications: () => ["applications"] as const,
	application: (applicationId: string) => ["application", applicationId] as const,
	applicationRoles: (applicationId: string) => ["application-roles", applicationId] as const,
	applicationRedirectUris: (applicationId: string) => {
		return ["application-redirect-uris", applicationId] as const
	},
	dashboardStats: () => {
		return ["dashboard-stats"] as const
	}
}

export const currentUserQueryOptions = queryOptions({
	queryKey: queryKeys.currentUser(),
	queryFn: async () => {
		const response = await api.manage.user.$get()
		return await response.json()
	}
})

export const applicationRedirectUrisQueryOptions = (applicationId: string) => {
	return queryOptions({
		queryKey: queryKeys.applicationRedirectUris(applicationId),
		queryFn: async () => {
			const response = await api.manage.applications[":appId"]["redirect-uris"].$get({
				param: { appId: applicationId }
			})
			return await response.json()
		}
	})
}

export const currentUserStatusQueryOptions = (userId: string) => {
	return queryOptions({
		queryKey: queryKeys.currentUserStatus(),
		queryFn: async () => {
			const response = await api.manage.users[":id"].access.$get({
				param: { id: userId },
				query: { appId: env.VITE_APPLICATION_ID }
			})
			return await response.json()
		}
	})
}

export const applicationsQueryOptions = queryOptions({
	queryKey: queryKeys.applications(),
	queryFn: async () => {
		const response = await api.manage.applications.$get()
		return await response.json()
	}
})

export const usersQueryOptions = queryOptions({
	queryKey: queryKeys.users(),
	queryFn: async () => {
		const response = await api.manage.users.$get()
		return await response.json()
	}
})

export const applicationQueryOptions = (applicationId: string) => {
	return queryOptions({
		enabled: !!applicationId,
		queryKey: queryKeys.application(applicationId),
		queryFn: async () => {
			const response = await api.manage.applications[":appId"].$get({
				param: { appId: applicationId }
			})
			return await response.json()
		}
	})
}

export const applicationRolesQueryOptions = (applicationId: string) => {
	return queryOptions({
		enabled: !!applicationId,
		queryKey: queryKeys.applicationRoles(applicationId),
		queryFn: async () => {
			const response = await api.manage.applications[":appId"].roles.$get({
				param: { appId: applicationId }
			})
			return await response.json()
		}
	})
}

export const userQueryOptions = (userId: string) => {
	return queryOptions({
		enabled: !!userId,
		queryKey: queryKeys.user(userId),
		queryFn: async () => {
			const response = await api.manage.users[":id"].$get({ param: { id: userId } })
			return await response.json()
		}
	})
}

export const userApplicationRolesQueryOptions = ({
	userId,
	appId
}: { userId: string; appId: string }) => {
	return queryOptions({
		enabled: !!userId && !!appId,
		queryKey: queryKeys.userApplicationRoles({ userId, appId }),
		queryFn: async () => {
			const response = await api.manage.users[":id"].roles.$get({
				param: { id: userId },
				query: { appId: appId }
			})
			return await response.json()
		}
	})
}

export const userApplicationsRolesQueryOptions = (userId: string) => {
	return queryOptions({
		enabled: !!userId,
		queryKey: queryKeys.userApplicationsRoles(userId),
		queryFn: async () => {
			const response = await api.manage.users[":id"]["applications-roles"].$get({
				param: { id: userId }
			})
			return await response.json()
		}
	})
}

export const userApplicationsAccessQueryOptions = (userId: string) => {
	return queryOptions({
		enabled: !!userId,
		queryKey: queryKeys.userApplicationsAccess(userId),
		queryFn: async () => {
			const response = await api.manage.users[":id"]["applications-access"].$get({
				param: { id: userId }
			})
			return await response.json()
		}
	})
}

export const applicationApiKeysQueryOptions = (appId: string) => {
	return queryOptions({
		queryKey: queryKeys.applicationApiKeys(appId),
		queryFn: async () => {
			const response = await api.manage[":appId"]["api-keys"].$get({
				param: {
					appId
				}
			})
			return await response.json()
		}
	})
}

export const dashboardStatsQueryOptions = queryOptions({
	queryKey: queryKeys.dashboardStats(),
	queryFn: async () => {
		const response = await api.manage.dashboard.stats.$get()
		return await response.json()
	}
})
