import { createRouter } from "@tanstack/react-router"

import { auth } from "./libs/auth"
import { queryClient } from "./libs/query-client"
import { routeTree } from "./routeTree.gen"
import { DefaultCatchBoundary } from "./shared/components/default-catch-boundary"
import { DefaultNotFound } from "./shared/components/default-not-found"
import { LoadingProgress } from "./shared/components/loading-progress"

export const router = createRouter({
	routeTree,
	scrollRestoration: true,
	defaultPreloadStaleTime: 0,
	context: { queryClient, auth },
	scrollRestorationBehavior: "smooth",
	defaultPendingComponent: () => <LoadingProgress />,
	defaultNotFoundComponent: () => <DefaultNotFound />,
	defaultErrorComponent: (error) => <DefaultCatchBoundary {...error} />
})
