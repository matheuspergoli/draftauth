import {
	type ErrorComponentProps,
	Link,
	rootRouteId,
	useMatch,
	useRouter
} from "@tanstack/react-router"
import { ArrowLeft, Home, RefreshCw } from "lucide-react"
import { Button } from "./button"

export const DefaultCatchBoundary = ({ error }: ErrorComponentProps) => {
	const router = useRouter()
	const isRoot = useMatch({
		strict: false,
		select: (state) => state.id === rootRouteId
	})

	const errorMessage = error?.message || "Ocorreu um erro inesperado"

	return (
		<div className="flex min-h-[400px] w-full flex-col items-center justify-center gap-6 p-8 text-center bg-background">
			<div className="space-y-4 max-w-md">
				<div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-red-100 text-red-600 mb-2">
					<svg
						xmlns="http://www.w3.org/2000/svg"
						className="h-8 w-8"
						fill="none"
						viewBox="0 0 24 24"
						stroke="currentColor"
					>
						<path
							strokeLinecap="round"
							strokeLinejoin="round"
							strokeWidth={2}
							d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
						/>
					</svg>
				</div>
				<h2 className="text-2xl font-bold">Ops...</h2>
				<p>{errorMessage}</p>

				{error?.stack && import.meta.env.DEV && (
					<div className="mt-4 p-4 bg-gray-100 rounded-md overflow-x-auto text-left">
						<pre className="text-xs text-red-600 whitespace-pre-wrap">{error.stack}</pre>
					</div>
				)}
			</div>

			<div className="flex flex-wrap items-center justify-center gap-3 mt-2">
				<Button
					variant="default"
					className="flex gap-2 items-center"
					onClick={() => void router.invalidate()}
				>
					<RefreshCw className="w-4 h-4" />
					<span>Tentar novamente</span>
				</Button>

				{isRoot ? (
					<Button variant="outline" asChild className="flex gap-2 items-center">
						<Link to="/">
							<Home className="w-4 h-4" />
							<span>Página inicial</span>
						</Link>
					</Button>
				) : (
					<Button variant="outline" asChild className="flex gap-2 items-center">
						<Link
							to="/"
							onClick={(e) => {
								e.preventDefault()
								window.history.back()
							}}
						>
							<ArrowLeft className="w-4 h-4" />
							<span>Voltar</span>
						</Link>
					</Button>
				)}
			</div>
		</div>
	)
}
