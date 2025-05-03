import { Layout } from "@openauthjs/openauth/ui/base"

export const AccessDeniedPage = () => {
	return (
		<Layout>
			<h1
				style={{
					fontSize: "18px",
					textAlign: "center"
				}}
			>
				Acesso Negado
			</h1>

			<p
				style={{
					fontSize: "14px",
					textAlign: "center"
				}}
			>
				Você não possui permissão para acessar este recurso. Entre em contato com o
				administrador do sistema se acredita que isso é um erro.
			</p>

			<button
				type="button"
				data-color="ghost"
				data-component="button"
				onClick={() => window.history.back()}
			>
				Voltar
			</button>
		</Layout>
	)
}
