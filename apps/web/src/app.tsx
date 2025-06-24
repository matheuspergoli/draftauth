import { RouterProvider } from "@tanstack/react-router"
import { QueryClientProvider } from "@tanstack/react-query"
import { queryClient } from "./libs/query-client"
import { router } from "./router"
import { ThemeProvider } from "./shared/components/theming"

const InnerApp = () => {
	return <RouterProvider router={router} />
}

export const App = () => {
	return (
		<QueryClientProvider client={queryClient}>
			<ThemeProvider defaultColorMode="dark" defaultTheme="default">
				<InnerApp />
			</ThemeProvider>
		</QueryClientProvider>
	)
}
