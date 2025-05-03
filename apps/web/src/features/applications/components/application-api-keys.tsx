import type { api } from "@/libs/api"
import {
	AlertDialog,
	AlertDialogAction,
	AlertDialogCancel,
	AlertDialogContent,
	AlertDialogDescription,
	AlertDialogFooter,
	AlertDialogHeader,
	AlertDialogTitle,
	AlertDialogTrigger
} from "@/shared/components/alert-dialog"
import { Button } from "@/shared/components/button"
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle
} from "@/shared/components/card"
import { Input } from "@/shared/components/input"
import { Label } from "@/shared/components/label"
import { applicationApiKeysQueryOptions } from "@/shared/queries"
import { useSuspenseQuery } from "@tanstack/react-query"
import { useParams } from "@tanstack/react-router"
import { format } from "date-fns"
import { ptBR } from "date-fns/locale"
import type { InferResponseType } from "hono"
import { EyeIcon, EyeOffIcon, KeyIcon, PlusIcon, Trash } from "lucide-react"
import React from "react"
import { useCreateApiKey } from "../hooks/use-create-api-key"
import { useRevokeApiKey } from "../hooks/use-revoke-api-key"

type ApplicationApiKey = InferResponseType<(typeof api.manage)[":appId"]["api-keys"]["$post"]>

type DialogState =
	| { status: "closed" }
	| { status: "creating" }
	| { status: "displaying"; key: ApplicationApiKey; showSecret: boolean }

export const ApplicationApiKeys = () => {
	const { appId } = useParams({ from: "/dashboard/applications/$appId" })
	const { data } = useSuspenseQuery(applicationApiKeysQueryOptions(appId))

	const [dialogState, setDialogState] = React.useState<DialogState>({ status: "closed" })

	const { mutateAsync: revokeApiKey, isPending: revokeIsPending } = useRevokeApiKey()
	const { mutateAsync: createApiKey, isPending: createIsPending } = useCreateApiKey()

	const toggleSecretVisibility = () => {
		if (dialogState.status === "displaying") {
			setDialogState({
				...dialogState,
				showSecret: !dialogState.showSecret
			})
		}
	}

	return (
		<Card>
			<CardHeader>
				<div className="flex justify-between">
					<div>
						<CardTitle>API Keys</CardTitle>
						<CardDescription>Gerencie as API Keys dessa aplicação</CardDescription>
					</div>
					<AlertDialog>
						<AlertDialogTrigger asChild>
							<Button onClick={() => setDialogState({ status: "creating" })}>
								<PlusIcon />
								Gerar API Key
							</Button>
						</AlertDialogTrigger>
						<AlertDialogContent>
							{dialogState.status === "creating" && (
								<>
									<AlertDialogHeader>
										<AlertDialogTitle>Gerar nova API Key</AlertDialogTitle>
										<AlertDialogDescription>
											Você só poderá visualizá-la uma única vez!
										</AlertDialogDescription>
									</AlertDialogHeader>
									<AlertDialogFooter>
										<AlertDialogCancel>Cancelar</AlertDialogCancel>
										<Button
											mode="loading"
											isLoading={createIsPending}
											onClick={async () => {
												const newApiKey = await createApiKey({ appId })
												setDialogState({
													key: newApiKey,
													showSecret: false,
													status: "displaying"
												})
											}}
										>
											Gerar
										</Button>
									</AlertDialogFooter>
								</>
							)}

							{dialogState.status === "displaying" && (
								<>
									<AlertDialogHeader>
										<AlertDialogTitle>API Key criada</AlertDialogTitle>
										<AlertDialogDescription>
											Guarde essa API Key de forma segura, não será possível ver novamente!
										</AlertDialogDescription>
									</AlertDialogHeader>
									<div className="space-y-4 py-4">
										<div className="space-y-2">
											<Label htmlFor="keyId">ID da Chave</Label>
											<div className="flex">
												<Input
													id="keyId"
													value={dialogState.key.keyId}
													readOnly
													className="font-mono text-sm"
												/>
											</div>
										</div>
										<div className="space-y-2">
											<div className="flex justify-between">
												<Label htmlFor="secretKey">Chave Secreta</Label>
												<Button
													variant="ghost"
													size="sm"
													onClick={toggleSecretVisibility}
													className="h-6 px-2"
												>
													{dialogState.showSecret ? (
														<EyeOffIcon className="h-4 w-4" />
													) : (
														<EyeIcon className="h-4 w-4" />
													)}
												</Button>
											</div>
											<div className="relative">
												<Input
													id="secretKey"
													value={
														dialogState.showSecret ? dialogState.key.secretKey : "•".repeat(24)
													}
													readOnly
													className="font-mono text-sm"
												/>
											</div>
										</div>
									</div>
									<AlertDialogCancel>Terminar</AlertDialogCancel>
								</>
							)}
						</AlertDialogContent>
					</AlertDialog>
				</div>
			</CardHeader>
			<CardContent>
				{data.length === 0 ? (
					<div className="text-center py-4 text-muted-foreground">
						Nenhuma API Key configurada
					</div>
				) : (
					<div className="space-y-4">
						{data.map((key) => (
							<div
								key={key.keyId}
								className="flex flex-col md:flex-row md:items-center justify-between p-4 rounded-md border"
							>
								<div className="space-y-1 mb-2 md:mb-0">
									<div className="flex items-center gap-2">
										<KeyIcon className="h-4 w-4 text-muted-foreground" />
										<span className="font-mono text-sm font-medium">{key.keyId}</span>
									</div>

									<div className="text-sm text-muted-foreground">
										<span>
											Criado em:{" "}
											{format(new Date(key.createdAt), "dd 'de' MMMM 'de' yyyy 'às' HH:mm", {
												locale: ptBR
											})}
										</span>
									</div>
								</div>

								<AlertDialog>
									<AlertDialogTrigger asChild>
										<Button variant="destructive">
											<Trash />
										</Button>
									</AlertDialogTrigger>
									<AlertDialogContent>
										<AlertDialogHeader>
											<AlertDialogTitle>Tem absoluta certeza disso?</AlertDialogTitle>
											<AlertDialogDescription>
												Essa ação não pode ser desfeita e irá apagar junto todas as API Keys
												referentes a essa aplicação junto de todos os seus dados
											</AlertDialogDescription>
										</AlertDialogHeader>
										<AlertDialogFooter>
											<AlertDialogCancel>Cancelar</AlertDialogCancel>
											<AlertDialogAction
												asChild
												onClick={async () => {
													await revokeApiKey({ keyId: key.keyId })
												}}
											>
												<Button mode="loading" isLoading={revokeIsPending}>
													Apagar
												</Button>
											</AlertDialogAction>
										</AlertDialogFooter>
									</AlertDialogContent>
								</AlertDialog>
							</div>
						))}
					</div>
				)}
			</CardContent>
		</Card>
	)
}
