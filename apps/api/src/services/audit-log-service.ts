import { db } from "@/db/client"
import { auditLogs } from "@/db/schema"
import type { AppEventType, AuditLogEntry } from "@/libs/events"
import { desc } from "drizzle-orm"

interface AuditEventData {
	eventType: AppEventType
	actorUserId?: string | null
	actorIpAddress?: string | null
	targetUserId?: string | null
	targetAppId?: string | null
	targetRoleId?: string | null
	targetApiKeyId?: string | null
	details?: Record<string, unknown> | null
}

export const logAuditEvent = async (event: AuditEventData) => {
	await db.insert(auditLogs).values({
		timestamp: Date.now(),
		eventType: event.eventType,
		actorUserId: event.actorUserId,
		actorIpAddress: event.actorIpAddress,
		targetUserId: event.targetUserId,
		targetAppId: event.targetAppId,
		targetRoleId: event.targetRoleId,
		targetApiKeyId: event.targetApiKeyId,
		details: event.details ? JSON.stringify(event.details) : null
	})
}

export const getAuditLogs = async () => {
	const rawLogs = await db.query.auditLogs.findMany({
		orderBy: [desc(auditLogs.timestamp)]
	})

	return rawLogs.map((log) => {
		let parsedDetails = null
		if (log.details) {
			try {
				parsedDetails = JSON.parse(log.details)
			} catch (e) {
				parsedDetails = { error: "Falha ao parsear details" }
			}
		}

		return {
			...log,
			details: parsedDetails
		} as AuditLogEntry
	})
}
