import React from "react"
import { Progress } from "./progress"

export const LoadingProgress = () => {
	const [progress, setProgress] = React.useState(0)

	React.useEffect(() => {
		const timer = setTimeout(() => setProgress(66))
		return () => clearTimeout(timer)
	}, [])

	return (
		<div className="flex w-full flex-col items-center justify-center bg-background p-4">
			<div className="w-full max-w-md space-y-4">
				<h2 className="text-center text-2xl font-semibold text-foreground">Carregando</h2>
				<Progress value={progress} className="w-full" />
				<p className="text-center text-sm text-muted-foreground">
					{progress === 100 ? "Completo!" : `${Math.round(progress)}% completo`}
				</p>
			</div>
		</div>
	)
}
