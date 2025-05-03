import type { auth } from "@/libs/auth"
import { Toaster } from "@/shared/components/sonner"
import type { QueryClient } from "@tanstack/react-query"
import { ReactQueryDevtools } from "@tanstack/react-query-devtools"
import {
	HeadContent,
	Outlet,
	createRootRouteWithContext,
	redirect,
	stripSearchParams
} from "@tanstack/react-router"
import { TanStackRouterDevtools } from "@tanstack/react-router-devtools"
import { z } from "zod"

const defaultValues = {
	code: "",
	state: ""
}

const searchSchema = z.object({
	code: z.string().default(defaultValues.code),
	state: z.string().default(defaultValues.state)
})

export const Route = createRootRouteWithContext<{
	auth: typeof auth
	queryClient: QueryClient
}>()({
	component: Root,
	validateSearch: searchSchema,
	beforeLoad: async ({ search, context }) => {
		if (search.code && search.state) {
			await context.auth.callback(search)
			throw redirect({ to: "/dashboard" })
		}

		await context.auth.checkAuthStatus()
	},
	search: {
		middlewares: [stripSearchParams(defaultValues)]
	},
	head: () => ({
		meta: [{ title: "Draft Auth Admin" }]
	})
})

function Root() {
	return (
		<>
			<HeadContent />
			<Outlet />
			<Toaster />
			<TanStackRouterDevtools position="bottom-left" />
			<ReactQueryDevtools position="bottom" buttonPosition="bottom-right" />
		</>
	)
}
