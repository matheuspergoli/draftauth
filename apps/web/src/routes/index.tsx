import { auth } from "@/libs/auth"
import { Button } from "@/shared/components/button"
import {
	Card,
	CardContent,
	CardDescription,
	CardFooter,
	CardHeader,
	CardTitle
} from "@/shared/components/card"
import { createFileRoute } from "@tanstack/react-router"

export const Route = createFileRoute("/")({
	component: RouteComponent
})

function RouteComponent() {
	return (
		<main className="h-dvh w-screen flex flex-col items-center justify-center">
			<Card>
				<CardHeader className="text-center">
					<CardTitle>Draft Auth Admin</CardTitle>
					<CardDescription>Faça login para acessar o dashboard</CardDescription>
				</CardHeader>
				<CardContent>
					<Button className="w-full" onClick={async () => await auth.login()}>
						Login
					</Button>
				</CardContent>
				<CardFooter>Acesso restringido para administradores</CardFooter>
			</Card>
		</main>
	)
}
