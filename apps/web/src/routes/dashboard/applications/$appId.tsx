import { ApplicationApiKeys } from "@/features/applications/components/application-api-keys"
import { ApplicationDetails } from "@/features/applications/components/application-details"
import { ApplicationRedirectUris } from "@/features/applications/components/application-redirect-uris"
import { ApplicationRoles } from "@/features/applications/components/application-roles"
import { PageTitle } from "@/shared/components/page-title"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/shared/components/tabs"
import {
	applicationApiKeysQueryOptions,
	applicationQueryOptions,
	applicationRedirectUrisQueryOptions,
	applicationRolesQueryOptions
} from "@/shared/queries"
import { createFileRoute, redirect } from "@tanstack/react-router"

export const Route = createFileRoute("/dashboard/applications/$appId")({
	component: RouteComponent,
	loader: async ({ context, params: { appId } }) => {
		const application = await context.queryClient.fetchQuery(applicationQueryOptions(appId))

		if (!application) throw redirect({ to: "/dashboard/applications" })

		await Promise.all([
			context.queryClient.prefetchQuery(applicationQueryOptions(appId)),
			context.queryClient.prefetchQuery(applicationRolesQueryOptions(appId)),
			context.queryClient.prefetchQuery(applicationApiKeysQueryOptions(appId)),
			context.queryClient.prefetchQuery(applicationRedirectUrisQueryOptions(appId))
		])
	}
})

function RouteComponent() {
	return (
		<main>
			<PageTitle>Detalhes da Aplicação</PageTitle>

			<Tabs defaultValue="details">
				<TabsList className="mb-5">
					<TabsTrigger value="details">Detalhes</TabsTrigger>
					<TabsTrigger value="api-keys">API Keys</TabsTrigger>
					<TabsTrigger value="redirect-uris">URIs de Redirecionamento</TabsTrigger>
					<TabsTrigger value="app-roles">Cargos da Aplicação</TabsTrigger>
				</TabsList>

				<TabsContent value="details">
					<ApplicationDetails />
				</TabsContent>

				<TabsContent value="api-keys">
					<ApplicationApiKeys />
				</TabsContent>

				<TabsContent value="redirect-uris">
					<ApplicationRedirectUris />
				</TabsContent>

				<TabsContent value="app-roles">
					<ApplicationRoles />
				</TabsContent>
			</Tabs>
		</main>
	)
}
