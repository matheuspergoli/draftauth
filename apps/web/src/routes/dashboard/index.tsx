import { Card, CardContent, CardHeader, CardTitle } from "@/shared/components/card"
import { PageTitle } from "@/shared/components/page-title"
import { dashboardStatsQueryOptions } from "@/shared/queries"
import { useSuspenseQuery } from "@tanstack/react-query"
import { createFileRoute } from "@tanstack/react-router"
import { AppWindow, ShieldCheck, Users } from "lucide-react"

export const Route = createFileRoute("/dashboard/")({
	component: RouteComponent,
	loader: async ({ context }) => {
		await context.queryClient.prefetchQuery(dashboardStatsQueryOptions)
	}
})

function RouteComponent() {
	const { data } = useSuspenseQuery(dashboardStatsQueryOptions)

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
		</main>
	)
}
