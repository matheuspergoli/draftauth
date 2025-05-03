import { Link } from "@tanstack/react-router"
import type { ReactNode } from "react"
import { Button } from "./button"

export const DefaultNotFound = ({ children }: { children?: ReactNode }) => {
	return (
		<div className="flex h-screen w-screen flex-col items-center justify-center gap-3">
			<div className="text-gray-600 dark:text-gray-400">
				{children ?? <p>A página que você estava procurando não existe.</p>}
			</div>
			<p className="flex flex-wrap items-center gap-2">
				<Button onClick={() => window.history.back()}>Voltar</Button>
				<Button asChild>
					<Link to="/">Tentar novamente</Link>
				</Button>
			</p>
		</div>
	)
}
