import { Outlet, createFileRoute } from "@tanstack/react-router"

export const Route = createFileRoute("/dashboard/applications")({
	component: RouteComponent,
	beforeLoad: ({ context }) => {
		if (context.ability.cannot("view_application", "Application")) {
			throw new Error("Você não tem permissão para ver essa página")
		}
	}
})

function RouteComponent() {
	return <Outlet />
}
