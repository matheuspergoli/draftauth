/** @jsxImportSource react */

import {
	Body,
	Container,
	Head,
	Heading,
	Hr,
	Html,
	Preview,
	Section,
	Text
} from "@react-email/components"

interface VerificationEmailProps {
	code: string
}

export const PINCodeEmail = ({ code = "123456" }: VerificationEmailProps) => {
	return (
		<Html>
			<Head />
			<Preview>Seu código de verificação para acesso</Preview>
			<Body style={main}>
				<Container style={container}>
					<Heading style={heading}>Código PIN</Heading>
					<Text style={paragraph}>
						Recebemos uma solicitação de acesso para seu endereço de email. Use o código abaixo
						para completar o processo:
					</Text>
					<Section style={codeContainer}>
						<Text style={verificationCodeStyle}>{code}</Text>
					</Section>
					<Text style={paragraph}>
						Se você não solicitou este código, por favor ignore este email ou entre em contato
						com nosso suporte se tiver alguma dúvida.
					</Text>
					<Hr style={hr} />
					<Text style={footer}>&copy; {new Date().getFullYear()} Draft Auth.</Text>
				</Container>
			</Body>
		</Html>
	)
}

export default PINCodeEmail

const main = {
	backgroundColor: "#f6f9fc",
	fontFamily:
		'-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif',
	padding: "20px 0"
}

const container = {
	backgroundColor: "#ffffff",
	border: "1px solid #e6ebf1",
	borderRadius: "5px",
	boxShadow: "0 5px 10px rgba(20, 50, 70, 0.2)",
	margin: "0 auto",
	maxWidth: "600px",
	padding: "20px"
}

const heading = {
	color: "#333",
	fontSize: "24px",
	fontWeight: "bold",
	textAlign: "center" as const,
	margin: "30px 0"
}

const paragraph = {
	color: "#333",
	fontSize: "16px",
	lineHeight: "26px",
	margin: "16px 0",
	textAlign: "center" as const
}

const codeContainer = {
	background: "#f4f4f4",
	borderRadius: "5px",
	margin: "30px auto",
	padding: "15px",
	textAlign: "center" as const,
	width: "200px"
}

const verificationCodeStyle = {
	color: "#333",
	display: "inline-block",
	fontFamily: "monospace",
	fontSize: "32px",
	fontWeight: "bold",
	letterSpacing: "6px",
	padding: "10px 0"
}

const hr = {
	borderColor: "#e6ebf1",
	margin: "30px 0"
}

const footer = {
	color: "#8898aa",
	fontSize: "12px",
	lineHeight: "22px",
	textAlign: "center" as const
}
