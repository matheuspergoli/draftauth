import { QueryCache, matchQuery } from "@tanstack/react-query"
import { MutationCache, QueryClient } from "@tanstack/react-query"
import { toast } from "sonner"

export const queryClient = new QueryClient({
	defaultOptions: {
		queries: {
			refetchOnWindowFocus: false,
			staleTime: Number.POSITIVE_INFINITY
		}
	},
	queryCache: new QueryCache({
		onError: (error) => {
			toast.error(error.message, {
				action: {
					label: "Tentar novamente",
					onClick: () => {
						queryClient.invalidateQueries()
					}
				}
			})
		}
	}),
	mutationCache: new MutationCache({
		onSuccess: (_data, _variables, _context, mutation) => {
			queryClient.invalidateQueries({
				predicate: (query) => {
					return (
						mutation.meta?.invalidates?.some((queryKey) => {
							return matchQuery({ queryKey }, query)
						}) ?? true
					)
				}
			})
		}
	})
})
