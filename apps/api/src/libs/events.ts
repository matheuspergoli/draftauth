import type { applications, auditLogs, roles, userApplicationAccess, users } from "@/db/schema"
import { logAuditEvent } from "@/services/audit-log-service"
import { Emitter } from "@draftauth/events"

interface RoleCreatedPayloadData {
	newRole: typeof roles.$inferSelect
	details: {
		roleId: string
		roleName: string
		appId: string
	}
}

interface RoleAssignedPayloadData {
	userId: string
	roleId: string
	appId: string
	details: {
		userId: string
		roleId: string
		appId: string
		roleName: string
		userEmail: string
	}
}

interface ApiKeyCreatedPayloadData {
	metadata: { keyId: string; appId: string; createdAt: number }
	details: {
		keyId: string
		appId: string
	}
}

interface ApiKeyRevokedPayloadData {
	keyId: string
	appId: string
	details: {
		keyId: string
		appId: string
	}
}

interface UserCreatedPayloadData {
	newUser: typeof users.$inferSelect
	details: {
		userId: string
		email: string
		initialStatus: (typeof users.$inferSelect)["status"]
	}
}

interface UserStatusUpdatedPayloadData {
	userId: string
	oldStatus: (typeof users.$inferSelect)["status"]
	newStatus: (typeof users.$inferSelect)["status"]
	details: {
		userId: string
		oldStatus: (typeof users.$inferSelect)["status"]
		newStatus: (typeof users.$inferSelect)["status"]
	}
}

interface UserAccessUpdatedPayloadData {
	userId: string
	appId: string
	newStatus: (typeof userApplicationAccess.$inferSelect)["accessStatus"]
	details: {
		userId: string
		appId: string
		newStatus: (typeof userApplicationAccess.$inferSelect)["accessStatus"]
	}
}

interface AppCreatedPayloadData {
	newApp: typeof applications.$inferSelect
	details: {
		appId: string
		appName: string
	}
}

interface AppDeletedPayloadData {
	appId: string
	appName: string
	details: {
		appId: string
		appName: string
	}
}

interface AppRedirectUriAddedPayloadData {
	appId: string
	uri: string
	uriId: string
	details: {
		appId: string
		uri: string
		uriId: string
	}
}

interface AppRedirectUriDeletedPayloadData {
	appId: string
	uriId: string
	uri: string
	details: {
		appId: string
		uriId: string
		uri: string
	}
}

interface RoleUpdatedPayloadData {
	updatedRole: typeof roles.$inferSelect
	oldRoleName?: string
	details: {
		roleId: string
		newRoleName: string
		oldRoleName?: string
		appId: string
	}
}

interface RoleDeletedPayloadData {
	roleId: string
	roleName: string
	appId: string
	details: {
		roleId: string
		roleName: string
		appId: string
	}
}

export interface AppEventMap {
	"user.created": UserCreatedPayloadData
	"user.status.updated": UserStatusUpdatedPayloadData
	"user.role.assigned": RoleAssignedPayloadData
	"user.role.revoked": RoleAssignedPayloadData
	"user.access.updated": UserAccessUpdatedPayloadData

	"app.created": AppCreatedPayloadData
	"app.deleted": AppDeletedPayloadData
	"app.redirecturi.added": AppRedirectUriAddedPayloadData
	"app.redirecturi.deleted": AppRedirectUriDeletedPayloadData

	"apikey.created": ApiKeyCreatedPayloadData
	"apikey.revoked": ApiKeyRevokedPayloadData

	"role.created": RoleCreatedPayloadData
	"role.updated": RoleUpdatedPayloadData
	"role.deleted": RoleDeletedPayloadData
}

export type AppEventType = keyof AppEventMap

export type AuditLogEntry = {
	[K in AppEventType]: typeof auditLogs.$inferSelect & {
		eventType: K
		details: AppEventMap[K]["details"] | null
	}
}[AppEventType]

export const events = new Emitter<AppEventMap>()

export const registerAuditLogListeners = () => {
	events.on("role.created", async (event) => {
		await logAuditEvent({
			eventType: event.type,
			targetAppId: event.payload.newRole.appId,
			targetRoleId: event.payload.newRole.roleId,
			details: event.payload.details
		})
	})

	events.on("apikey.created", async (event) => {
		await logAuditEvent({
			eventType: event.type,
			targetApiKeyId: event.payload.metadata.keyId,
			targetAppId: event.payload.metadata.appId,
			details: event.payload.details
		})
	})

	events.on("apikey.revoked", async (event) => {
		await logAuditEvent({
			eventType: event.type,
			targetApiKeyId: event.payload.keyId,
			targetAppId: event.payload.appId,
			details: event.payload.details
		})
	})

	events.on("user.created", async (event) => {
		await logAuditEvent({
			eventType: event.type,
			targetUserId: event.payload.newUser.userId,
			details: event.payload.details
		})
	})

	events.on("user.status.updated", async (event) => {
		await logAuditEvent({
			eventType: event.type,
			targetUserId: event.payload.userId,
			details: event.payload.details
		})
	})

	events.on("user.role.assigned", async (event) => {
		await logAuditEvent({
			eventType: event.type,
			targetUserId: event.payload.userId,
			targetRoleId: event.payload.roleId,
			targetAppId: event.payload.appId,
			details: event.payload.details
		})
	})

	events.on("user.role.revoked", async (event) => {
		await logAuditEvent({
			eventType: event.type,
			targetUserId: event.payload.userId,
			targetRoleId: event.payload.roleId,
			targetAppId: event.payload.appId,
			details: event.payload.details
		})
	})

	events.on("user.access.updated", async (event) => {
		await logAuditEvent({
			eventType: event.type,
			targetUserId: event.payload.userId,
			targetAppId: event.payload.appId,
			details: event.payload.details
		})
	})

	events.on("app.created", async (event) => {
		await logAuditEvent({
			eventType: event.type,
			targetAppId: event.payload.newApp.appId,
			details: event.payload.details
		})
	})

	events.on("app.deleted", async (event) => {
		await logAuditEvent({
			eventType: event.type,
			targetAppId: event.payload.appId,
			details: event.payload.details
		})
	})

	events.on("app.redirecturi.added", async (event) => {
		await logAuditEvent({
			eventType: event.type,
			targetAppId: event.payload.appId,
			details: event.payload.details
		})
	})

	events.on("app.redirecturi.deleted", async (event) => {
		await logAuditEvent({
			eventType: event.type,
			targetAppId: event.payload.appId,
			details: event.payload.details
		})
	})

	events.on("role.updated", async (event) => {
		await logAuditEvent({
			eventType: event.type,
			targetRoleId: event.payload.updatedRole.roleId,
			targetAppId: event.payload.updatedRole.appId,
			details: event.payload.details
		})
	})

	events.on("role.deleted", async (event) => {
		await logAuditEvent({
			eventType: event.type,
			targetRoleId: event.payload.roleId,
			targetAppId: event.payload.appId,
			details: event.payload.details
		})
	})
}
