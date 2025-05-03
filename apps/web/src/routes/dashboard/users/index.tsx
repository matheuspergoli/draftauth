import { UsersTable, usersTableColumns } from "@/features/users/components/users-table"
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle
} from "@/shared/components/card"
import { PageTitle } from "@/shared/components/page-title"
import { usersQueryOptions } from "@/shared/queries"
import { useSuspenseQuery } from "@tanstack/react-query"
import { createFileRoute } from "@tanstack/react-router"

export const Route = createFileRoute("/dashboard/users/")({
	component: RouteComponent,
	loader: async ({ context }) => {
		await context.queryClient.prefetchQuery(usersQueryOptions)
	}
})

function RouteComponent() {
	const users = useSuspenseQuery(usersQueryOptions)

	return (
		<main>
			<PageTitle>Usuários</PageTitle>

			<Card>
				<CardHeader>
					<CardTitle>Todos usuários</CardTitle>
					<CardDescription>
						Gerencia as contas dos usuários e suas permissões entre aplicações
					</CardDescription>
				</CardHeader>
				<CardContent>
					<UsersTable columns={usersTableColumns} data={users.data} />
				</CardContent>
			</Card>
		</main>
	)
}
