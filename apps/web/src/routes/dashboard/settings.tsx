import { baseColors } from "@/libs/colors"
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle
} from "@/shared/components/card"
import { PageTitle } from "@/shared/components/page-title"
import {
	Select,
	SelectContent,
	SelectItem,
	SelectTrigger,
	SelectValue
} from "@/shared/components/select"
import { Switch } from "@/shared/components/switch"
import { useTheme } from "@/shared/components/theming"
import { createFileRoute } from "@tanstack/react-router"

export const Route = createFileRoute("/dashboard/settings")({
	component: RouteComponent,
	head: () => ({
		meta: [{ title: "Configurações" }]
	})
})

function RouteComponent() {
	const { colorMode, setColorMode, theme, setTheme } = useTheme()

	return (
		<main>
			<PageTitle>Configurações</PageTitle>

			<Card>
				<CardHeader>
					<CardTitle>Configurações Gerais</CardTitle>
					<CardDescription>Gerencie suas preferências gerais do sistema</CardDescription>
				</CardHeader>
				<CardContent className="space-y-5">
					<div>
						<p className="font-semibold">Tema escuro</p>
						<p className="text-foreground text-sm mb-2">
							Ative o tema escuro para reduzir o cansaço visual
						</p>
						<Switch
							className="cursor-pointer"
							defaultChecked={colorMode === "dark"}
							onCheckedChange={(check) => {
								check ? setColorMode("dark") : setColorMode("light")
							}}
						/>
					</div>
					<div>
						<p className="font-semibold">Tema de cores</p>
						<p className="text-foreground text-sm mb-2">
							Escolha um tema de cores para o seu sistema
						</p>
						<Select
							defaultValue={theme}
							onValueChange={(value) => setTheme(value as typeof theme)}
						>
							<SelectTrigger className="w-[240px]">
								<SelectValue placeholder="Escolha um tema" />
							</SelectTrigger>
							<SelectContent>
								{Object.entries(baseColors).map(([_, value]) => (
									<SelectItem key={value.name} value={value.name}>
										{value.label}
									</SelectItem>
								))}
							</SelectContent>
						</Select>
					</div>
				</CardContent>
			</Card>
		</main>
	)
}
