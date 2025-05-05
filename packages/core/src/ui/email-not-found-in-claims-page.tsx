import { Layout } from "@openauthjs/openauth/ui/base"

export const EmailNotFoundInClaimsPage = () => {
	return (
		<Layout>
			<h1
				style={{
					fontSize: "18px",
					textAlign: "center"
				}}
			>
				Email Não Encontrado
			</h1>

			<p
				style={{
					fontSize: "15px",
					textAlign: "center"
				}}
			>
				Não foi possível obter seu email durante o processo de autenticação.
			</p>

			<p
				style={{
					fontSize: "14px",
					textAlign: "center"
				}}
			>
				Isso pode ocorrer se você não concedeu permissão para acessar seu email ou se houve um
				problema durante a autenticação.
			</p>

			<button
				type="button"
				data-color="ghost"
				data-component="button"
				onClick={() => window.history.back()}
			>
				Tentar Novamente
			</button>
		</Layout>
	)
}
