import { MainSidebar } from "@/shared/components/app-sidebar/main-sidebar"
import { Separator } from "@/shared/components/separator"
import { SidebarInset, SidebarProvider, SidebarTrigger } from "@/shared/components/sidebar"
import { currentUserQueryOptions, currentUserStatusQueryOptions } from "@/shared/queries"
import { Outlet, createFileRoute, redirect } from "@tanstack/react-router"

export const Route = createFileRoute("/dashboard")({
	component: RouteComponent,
	beforeLoad: async ({ context }) => {
		const { isAuthenticated } = await context.auth.checkAuthStatus()

		if (!isAuthenticated) {
			await context.auth.logout()
			throw redirect({ to: "/" })
		}

		const user = await context.queryClient.fetchQuery(currentUserQueryOptions)
		const userStatus = await context.queryClient.fetchQuery(
			currentUserStatusQueryOptions(user.userId)
		)

		if (userStatus.status === "disabled") {
			await context.auth.logout()
			throw redirect({ to: "/" })
		}

		if (!user.isOwner) {
			await context.auth.logout()
			throw redirect({ to: "/" })
		}
	}
})

function RouteComponent() {
	return (
		<SidebarProvider>
			<MainSidebar />
			<SidebarInset>
				<header className="flex h-16 shrink-0 items-center gap-2 border-b">
					<div className="flex items-center gap-2 px-4">
						<SidebarTrigger className="-ml-1" />
						<Separator orientation="vertical" className="mr-2 h-4" />
					</div>
				</header>
				<div className="container my-5 px-4 mx-auto">
					<Outlet />
				</div>
			</SidebarInset>
		</SidebarProvider>
	)
}
