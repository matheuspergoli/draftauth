import { env } from "@/environment/env"
import { run } from "@/libs/utils"
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle
} from "@/shared/components/card"
import { Input } from "@/shared/components/input"
import { Label } from "@/shared/components/label"
import { applicationQueryOptions } from "@/shared/queries"
import { useSuspenseQuery } from "@tanstack/react-query"
import { useParams } from "@tanstack/react-router"
import { DeleteApplicationDialog } from "./delete-application-dialog"

export const ApplicationDetails = () => {
	const { appId } = useParams({ from: "/dashboard/applications/$appId" })
	const { data } = useSuspenseQuery(applicationQueryOptions(appId))

	return (
		<Card>
			<CardHeader className="flex justify-between">
				<div>
					<CardTitle>Informações da Aplicação</CardTitle>
					<CardDescription>Informações básicas da aplicação</CardDescription>
				</div>

				{run(() => {
					if (appId !== env.VITE_APPLICATION_ID) {
						return <DeleteApplicationDialog appId={appId} />
					}

					return null
				})}
			</CardHeader>
			<CardContent className="flex items-center [&>*]:flex-1 gap-5">
				<fieldset className="space-y-1">
					<Label>Nome da Aplicação</Label>
					<Input value={data.appName} disabled />
				</fieldset>

				<fieldset className="space-y-1">
					<Label>ID da Aplicação</Label>
					<Input value={data.appId} disabled />
				</fieldset>
			</CardContent>
		</Card>
	)
}
