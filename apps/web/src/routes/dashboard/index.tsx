import { api } from "@/libs/api"
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle
} from "@/shared/components/card"
import { PageTitle } from "@/shared/components/page-title"
import { dashboardStatsQueryOptions } from "@/shared/queries"
import type { AppEventType, AuditLogEntry } from "@draftauth/types"
import { useSuspenseQuery } from "@tanstack/react-query"
import { createFileRoute } from "@tanstack/react-router"
import { formatDistanceToNow } from "date-fns"
import { ptBR } from "date-fns/locale"
import {
	AppWindow,
	Ban,
	Edit3,
	FilePlus,
	KeyRound,
	ListChecks,
	ShieldCheck,
	Trash2,
	UserCog,
	UserPlus,
	Users
} from "lucide-react"

export const Route = createFileRoute("/dashboard/")({
	component: RouteComponent,
	loader: async ({ context }) => {
		await context.queryClient.prefetchQuery(dashboardStatsQueryOptions)
	}
})

const eventDisplayMap: Record<AppEventType, { icon: React.ElementType; title: string }> = {
	"user.created": { icon: UserPlus, title: "Usuário Criado" },
	"user.status.updated": { icon: UserCog, title: "Status do Usuário Atualizado" },
	"user.role.assigned": { icon: ShieldCheck, title: "Cargo Atribuído a Usuário" },
	"user.role.revoked": { icon: Ban, title: "Cargo Revogado de Usuário" },
	"user.access.updated": { icon: UserCog, title: "Acesso de Usuário Atualizado" },
	"app.created": { icon: AppWindow, title: "Aplicação Criada" },
	"app.deleted": { icon: Trash2, title: "Aplicação Deletada" },
	"app.redirecturi.added": { icon: FilePlus, title: "URI de App Adicionada" },
	"app.redirecturi.deleted": { icon: Trash2, title: "URI de App Deletada" },
	"apikey.created": { icon: KeyRound, title: "API Key Criada" },
	"apikey.revoked": { icon: Ban, title: "API Key Revogada" },
	"role.created": { icon: ShieldCheck, title: "Cargo Criado" },
	"role.updated": { icon: Edit3, title: "Cargo Atualizado" },
	"role.deleted": { icon: Trash2, title: "Cargo Deletado" }
}

const formatLogDescription = (log: AuditLogEntry) => {
	const { eventType, details, actorUserId, targetUserId, targetAppId, targetRoleId } = log

	const actor = actorUserId ? `Ator ${actorUserId.substring(0, 8)}...` : "Sistema"

	switch (eventType) {
		case "user.created":
			return `${actor} criou o usuário ${details?.email || targetUserId}.`
		case "user.status.updated":
			return `${actor} atualizou o status de ${details?.userId || targetUserId} para ${details?.newStatus}. (Anterior: ${details?.oldStatus})`
		case "user.role.assigned":
			return `${actor} atribuiu o cargo ${details?.roleName || targetRoleId} ao usuário ${details?.userEmail || targetUserId} na app ${details?.appId || targetAppId}.`
		case "user.role.revoked":
			return `${actor} revogou o cargo ${details?.roleName || targetRoleId} do usuário ${details?.userEmail || targetUserId} na app ${details?.appId || targetAppId}.`
		case "user.access.updated":
			return `${actor} atualizou o acesso do usuário ${details?.userId || targetUserId} para a app ${details?.appId || targetAppId} para ${details?.newStatus}.`
		case "app.created":
			return `${actor} criou a aplicação ${details?.appName || targetAppId}.`
		case "app.deleted":
			return `${actor} deletou a aplicação ${details?.appName || targetAppId}.`
		case "app.redirecturi.added":
			return `${actor} adicionou a URI '${details?.uri}' à aplicação ${details?.appId || targetAppId}.`
		case "app.redirecturi.deleted":
			return `${actor} removeu uma URI da aplicação ${details?.appId || targetAppId}.`
		case "apikey.created":
			return `${actor} criou uma API key (${details?.keyId?.substring(0, 12)}...) para a aplicação ${details?.appId || targetAppId}.`
		case "apikey.revoked":
			return `${actor} revogou a API key (${details?.keyId?.substring(0, 12)}...) da aplicação ${details?.appId || targetAppId}.`
		case "role.created":
			return `${actor} criou o cargo '${details?.roleName || targetRoleId}' na aplicação ${details?.appId || targetAppId}.`
		case "role.updated":
			return `${actor} atualizou o cargo ${details?.oldRoleName || targetRoleId} para '${details?.newRoleName}' na aplicação ${details?.appId || targetAppId}.`
		case "role.deleted":
			return `${actor} deletou o cargo '${details?.roleName || targetRoleId}' da aplicação ${details?.appId || targetAppId}.`
		default: {
			let genericDesc = `${actor} realizou a ação '${eventType}'.`
			if (targetUserId) genericDesc += ` Usuário alvo: ${targetUserId.substring(0, 8)}.`
			if (targetAppId) genericDesc += ` App alvo: ${targetAppId}.`
			if (targetRoleId) genericDesc += ` Role alvo: ${targetRoleId.substring(0, 8)}.`
			return genericDesc
		}
	}
}

function RouteComponent() {
	const { data } = useSuspenseQuery(dashboardStatsQueryOptions)
	const { data: logs } = useSuspenseQuery({
		queryKey: ["audit-logs"],
		queryFn: async () => {
			const response = await api.manage["audit-logs"].$get()
			return await response.json()
		}
	})

	return (
		<main>
			<PageTitle>Dashboard</PageTitle>

			<section className="grid grid-cols-3 gap-3 mb-3">
				<Card>
					<CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
						<CardTitle className="text-sm font-medium">Total de Usuários</CardTitle>
						<Users className="h-4 w-4 text-muted-foreground" />
					</CardHeader>

					<CardContent className="text-2xl font-bold">{data.totalUsers}</CardContent>
				</Card>

				<Card>
					<CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
						<CardTitle className="text-sm font-medium">Total de Aplicações</CardTitle>
						<AppWindow className="h-4 w-4 text-muted-foreground" />
					</CardHeader>

					<CardContent className="text-2xl font-bold">{data.activeApplications}</CardContent>
				</Card>

				<Card>
					<CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
						<CardTitle className="text-sm font-medium">Total de Cargos</CardTitle>
						<ShieldCheck className="h-4 w-4 text-muted-foreground" />
					</CardHeader>

					<CardContent className="text-2xl font-bold">{data.rolesDefined}</CardContent>
				</Card>
			</section>

			<section className="mt-6">
				<Card>
					<CardHeader>
						<CardTitle className="flex items-center gap-2">
							<ListChecks className="h-5 w-5" />
							Atividade Recente
						</CardTitle>
						<CardDescription>Últimas ações importantes no sistema.</CardDescription>
					</CardHeader>
					<CardContent>
						{logs && logs.length > 0 ? (
							<ul className="space-y-3">
								{logs.slice(0, 5).map((log) => {
									const displayInfo = eventDisplayMap[log.eventType]
									const IconComponent = displayInfo.icon
									return (
										<li
											key={log.logId}
											className="flex items-start space-x-3 border-b border-border/60 pb-3 last:border-b-0 last:pb-0"
										>
											<div className="mt-1 flex-shrink-0 bg-muted rounded-full p-2">
												<IconComponent className="h-4 w-4 text-muted-foreground" />
											</div>
											<div className="flex-1 min-w-0">
												<p className="text-sm font-medium text-foreground truncate">
													{displayInfo.title}
												</p>
												<p className="text-xs text-muted-foreground">
													{formatLogDescription(log)}
												</p>
											</div>
											<div className="flex-shrink-0 text-xs text-muted-foreground whitespace-nowrap pt-1">
												{formatDistanceToNow(new Date(log.timestamp), {
													addSuffix: true,
													locale: ptBR
												})}
											</div>
										</li>
									)
								})}
							</ul>
						) : (
							<p className="text-sm text-muted-foreground text-center py-4">
								Nenhuma atividade recente para exibir.
							</p>
						)}
					</CardContent>
				</Card>
			</section>
		</main>
	)
}
