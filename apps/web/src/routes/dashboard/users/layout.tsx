import { Outlet, createFileRoute } from "@tanstack/react-router"

export const Route = createFileRoute("/dashboard/users")({
	component: RouteComponent,
	beforeLoad: ({ context }) => {
		if (context.ability.cannot("view_user", "User")) {
			throw new Error("Você não tem permissão para ver essa página")
		}
	}
})

function RouteComponent() {
	return <Outlet />
}
