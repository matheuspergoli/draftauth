import { QueryClientProvider } from "@tanstack/react-query"
import { RouterProvider } from "@tanstack/react-router"

import { queryClient } from "./libs/query-client"
import { router } from "./router"
import { ThemeProvider } from "./shared/components/theming"

const InnerApp = () => {
	return <RouterProvider router={router} />
}

export const App = () => {
	return (
		<QueryClientProvider client={queryClient}>
			<ThemeProvider defaultTheme="default" defaultColorMode="dark">
				<InnerApp />
			</ThemeProvider>
		</QueryClientProvider>
	)
}
