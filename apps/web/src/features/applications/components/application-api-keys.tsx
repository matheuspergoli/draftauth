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
import { AlertTriangle, Download, KeyIcon, PlusIcon, Trash } from "lucide-react"
import React from "react"
import { useCreateApiKey } from "../hooks/use-create-api-key"
import { useRevokeApiKey } from "../hooks/use-revoke-api-key"

type ApplicationApiKey = InferResponseType<(typeof api.manage)[":appId"]["api-keys"]["$post"]>

type DialogState =
	| { status: "closed" }
	| { status: "creating" }
	| { status: "displaying"; value: ApplicationApiKey }

export const ApplicationApiKeys = () => {
	const { appId } = useParams({ from: "/dashboard/applications/$appId" })
	const { data } = useSuspenseQuery(applicationApiKeysQueryOptions(appId))

	const [dialogState, setDialogState] = React.useState<DialogState>({ status: "closed" })

	const { mutateAsync: revokeApiKey, isPending: revokeIsPending } = useRevokeApiKey()
	const { mutateAsync: createApiKey, isPending: createIsPending } = useCreateApiKey()

	const handleDownload = (keyFileData: string, keyId: string) => {
		const blob = new Blob([keyFileData], { type: "text/plain;charset=utf-8" })
		const url = URL.createObjectURL(blob)
		const link = document.createElement("a")
		link.href = url
		link.download = `draftauth_api_key_${keyId}.txt`
		document.body.appendChild(link)
		link.click()
		document.body.removeChild(link)
		URL.revokeObjectURL(url)
	}

	return (
		<Card>
			<CardHeader>
				<div className="flex justify-between">
					<div>
						<CardTitle>API Keys</CardTitle>
						<CardDescription>Gerencie as API Keys dessa aplicação</CardDescription>
					</div>
					<AlertDialog
						open={dialogState.status !== "closed"}
						onOpenChange={(open) => !open && setDialogState({ status: "closed" })}
					>
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
											Um arquivo contendo o ID e a Chave Secreta será gerado para download.
											<strong className="text-destructive block mt-2">
												<AlertTriangle className="inline-block h-4 w-4 mr-1" />
												Guarde este arquivo em local seguro! A chave secreta não poderá ser
												recuperada.
											</strong>
										</AlertDialogDescription>
									</AlertDialogHeader>
									<AlertDialogFooter>
										<AlertDialogCancel onClick={() => setDialogState({ status: "closed" })}>
											Cancelar
										</AlertDialogCancel>
										<Button
											mode="loading"
											isLoading={createIsPending}
											onClick={async () => {
												const newApiKeyData = await createApiKey({ appId })
												setDialogState({
													status: "displaying",
													value: newApiKeyData
												})
											}}
										>
											Gerar Chave
										</Button>
									</AlertDialogFooter>
								</>
							)}

							{dialogState.status === "displaying" && (
								<>
									<AlertDialogHeader>
										<AlertDialogTitle>API Key Gerada</AlertDialogTitle>
										<AlertDialogDescription>
											<strong className="text-destructive block mt-2">
												<AlertTriangle className="inline-block h-4 w-4 mr-1" />
												Faça o download do arquivo agora e guarde-o em local seguro. A chave
												secreta não será exibida novamente.
											</strong>
										</AlertDialogDescription>
									</AlertDialogHeader>
									<div className="space-y-4 py-4">
										<div className="space-y-2">
											<Label htmlFor="keyId">ID da Chave (Key ID)</Label>
											<Input
												id="keyId"
												value={dialogState.value.metadata.keyId}
												readOnly
												className="font-mono text-sm"
											/>
											<p className="text-xs text-muted-foreground">
												Este ID é público e usado para identificar a chave.
											</p>
										</div>

										<Button
											onClick={() => {
												handleDownload(
													dialogState.value.keyFileData,
													dialogState.value.metadata.keyId
												)
											}}
											className="w-full"
										>
											<Download className="mr-2 h-4 w-4" />
											Baixar Arquivo da Chave (.txt)
										</Button>
									</div>
									<AlertDialogCancel onClick={() => setDialogState({ status: "closed" })}>
										Concluir
									</AlertDialogCancel>
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
										<Button variant="destructive" size="icon">
											<Trash />
										</Button>
									</AlertDialogTrigger>
									<AlertDialogContent>
										<AlertDialogHeader>
											<AlertDialogTitle>Tem absoluta certeza?</AlertDialogTitle>
											<AlertDialogDescription>
												Essa ação não pode ser desfeita e irá revogar permanentemente esta API
												Key.
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
												<Button
													mode="loading"
													variant="destructive"
													isLoading={revokeIsPending}
												>
													Revogar Chave
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
