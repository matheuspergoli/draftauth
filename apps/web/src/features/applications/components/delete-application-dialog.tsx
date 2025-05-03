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
import { useRouter } from "@tanstack/react-router"
import { Trash } from "lucide-react"
import { useDeleteApplication } from "../hooks/use-delete-application"

export const DeleteApplicationDialog = ({ appId }: { appId: string }) => {
	const router = useRouter()
	const { mutateAsync: deleteApplication, isPending } = useDeleteApplication()

	return (
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
						Essa ação não pode ser desfeita e irá apagar junto todas as API Keys referentes a
						essa aplicação junto de todos os seus dados
					</AlertDialogDescription>
				</AlertDialogHeader>
				<AlertDialogFooter>
					<AlertDialogCancel>Cancelar</AlertDialogCancel>
					<AlertDialogAction
						asChild
						onClick={async () => {
							await deleteApplication({ appId })
							router.navigate({ to: "/dashboard/applications" })
						}}
					>
						<Button mode="loading" isLoading={isPending}>
							Apagar
						</Button>
					</AlertDialogAction>
				</AlertDialogFooter>
			</AlertDialogContent>
		</AlertDialog>
	)
}
