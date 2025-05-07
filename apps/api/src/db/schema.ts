import { randomUUID } from "node:crypto"
import type { AppEventType } from "@/libs/events"
import { integer, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core"

export type UserStatus = "active" | "inactive"
export type AccessStatus = "enabled" | "disabled"
export type ProviderName = "github" | "google" | "password" | "code"

export const users = sqliteTable("users", {
	userId: text("user_id").primaryKey(),
	email: text("email").notNull().unique(),
	status: text("status").notNull().default("active").$type<UserStatus>(),
	createdAt: integer("created_at")
		.notNull()
		.$defaultFn(() => Date.now()),
	updatedAt: integer("updated_at")
		.notNull()
		.$defaultFn(() => Date.now())
		.$onUpdate(() => Date.now())
})

export const systemConfiguration = sqliteTable("system_configuration", {
	key: text("config_key").primaryKey(),
	value: text("config_value").notNull()
})

export const applicationApiKeys = sqliteTable("application_api_keys", {
	keyId: text("key_id").primaryKey(),
	appId: text("app_id")
		.notNull()
		.references(() => applications.appId, { onDelete: "cascade" }),
	encryptedSecretKey: text("encrypted_secret_key").notNull(),
	createdAt: integer("created_at")
		.notNull()
		.$defaultFn(() => Date.now())
})

export const applications = sqliteTable("applications", {
	appId: text("app_id").primaryKey(),
	appName: text("app_name").notNull()
})

export const roles = sqliteTable(
	"roles",
	{
		roleId: text("role_id")
			.primaryKey()
			.$defaultFn(() => randomUUID()),
		roleName: text("role_name").notNull(),
		appId: text("app_id")
			.notNull()
			.references(() => applications.appId, { onDelete: "cascade" })
	},
	(table) => {
		return [uniqueIndex("app_id_role_name_idx").on(table.appId, table.roleName)]
	}
)

export const userRoles = sqliteTable(
	"user_roles",
	{
		userRoleId: text("user_role_id")
			.primaryKey()
			.$defaultFn(() => randomUUID()),
		userId: text("user_id")
			.notNull()
			.references(() => users.userId, { onDelete: "cascade" }),
		roleId: text("role_id")
			.notNull()
			.references(() => roles.roleId, { onDelete: "cascade" })
	},
	(table) => {
		return [uniqueIndex("user_roles_user_id_role_id_idx").on(table.userId, table.roleId)]
	}
)

export const userExternalIdentities = sqliteTable(
	"user_external_identities",
	{
		identityId: text("identity_id")
			.primaryKey()
			.$defaultFn(() => randomUUID()),
		userId: text("user_id")
			.notNull()
			.references(() => users.userId, { onDelete: "cascade" }),
		providerName: text("provider_name").notNull().$type<ProviderName>(),
		providerUserId: text("provider_user_id").notNull()
	},
	(table) => {
		return [
			uniqueIndex("user_external_identities_provider_name_id_idx").on(
				table.providerName,
				table.providerUserId
			)
		]
	}
)

export const applicationRedirectUris = sqliteTable(
	"application_redirect_uris",
	{
		uriId: text("uri_id")
			.primaryKey()
			.$defaultFn(() => randomUUID()),
		appId: text("app_id")
			.notNull()
			.references(() => applications.appId, { onDelete: "cascade" }),
		uri: text("uri").notNull()
	},
	(table) => {
		return [uniqueIndex("app_redirect_uris_app_id_uri_idx").on(table.appId, table.uri)]
	}
)

export const userApplicationAccess = sqliteTable(
	"user_application_access",
	{
		userAccessId: text("user_access_id")
			.primaryKey()
			.$defaultFn(() => randomUUID()),
		userId: text("user_id")
			.notNull()
			.references(() => users.userId, { onDelete: "cascade" }),
		appId: text("app_id")
			.notNull()
			.references(() => applications.appId, { onDelete: "cascade" }),
		accessStatus: text("access_status").notNull().default("enabled").$type<AccessStatus>()
	},
	(table) => {
		return [
			uniqueIndex("user_application_access_user_id_app_id_idx").on(table.userId, table.appId)
		]
	}
)

export const auditLogs = sqliteTable("audit_logs", {
	logId: text("log_id")
		.primaryKey()
		.$defaultFn(() => randomUUID()),
	timestamp: integer("timestamp")
		.notNull()
		.$defaultFn(() => Date.now()),
	details: text("details"),
	eventType: text("event_type").notNull().$type<AppEventType>(),
	actorUserId: text("actor_user_id").references(() => users.userId, {
		onDelete: "set null"
	}),
	actorIpAddress: text("actor_ip_address"),
	targetUserId: text("target_user_id").references(() => users.userId, {
		onDelete: "set null"
	}),
	targetAppId: text("target_app_id").references(() => applications.appId, {
		onDelete: "set null"
	}),
	targetRoleId: text("target_role_id").references(() => roles.roleId, {
		onDelete: "set null"
	}),
	targetApiKeyId: text("target_api_key_id").references(() => applicationApiKeys.keyId, {
		onDelete: "set null"
	})
})
