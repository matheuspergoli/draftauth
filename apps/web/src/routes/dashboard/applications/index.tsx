import {
	ApplicationTable,
	applicationTableColumns
} from "@/features/applications/components/application-table"
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle
} from "@/shared/components/card"
import { PageTitle } from "@/shared/components/page-title"
import { applicationsQueryOptions } from "@/shared/queries"
import { useSuspenseQuery } from "@tanstack/react-query"
import { createFileRoute } from "@tanstack/react-router"

export const Route = createFileRoute("/dashboard/applications/")({
	component: RouteComponent,
	loader: async ({ context }) => {
		await context.queryClient.prefetchQuery(applicationsQueryOptions)
	}
})

function RouteComponent() {
	const { data } = useSuspenseQuery(applicationsQueryOptions)

	return (
		<main>
			<PageTitle>Aplicações</PageTitle>

			<Card>
				<CardHeader>
					<CardTitle>Todas aplicações</CardTitle>
					<CardDescription>
						Aplicações que usam Draft Auth para autenticação e autorização
					</CardDescription>
				</CardHeader>
				<CardContent>
					<ApplicationTable columns={applicationTableColumns} data={data} />
				</CardContent>
			</Card>
		</main>
	)
}
