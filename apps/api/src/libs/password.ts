import { createHash } from "node:crypto"
import zxcvbn, { type ZXCVBNFeedbackWarning } from "zxcvbn"

export const checkPasswordStrength = (password: string) => {
	const checkPasswordStrength = zxcvbn(password)

	return checkPasswordStrength
}

export const checkPasswordLeaks = async (password: string): Promise<boolean> => {
	try {
		const hash = createHash("sha1").update(password, "utf8").digest("hex")

		const hashPrefix = hash.slice(0, 5)
		const hashSuffix = hash.slice(5).toUpperCase()

		const response = await fetch(`https://api.pwnedpasswords.com/range/${hashPrefix}`, {
			method: "GET",
			headers: {
				"User-Agent": "Node.js CheckPasswordLeaks Script"
			}
		})

		if (response.ok) {
			const body = await response.text()
			const lines = body.split("\r\n")

			for (const line of lines) {
				const [suffixFromApi] = line.split(":")
				if (suffixFromApi === hashSuffix) {
					return true
				}
			}

			return false
		}
		return false
	} catch (error) {
		return false
	}
}

export const translateWarnings = (feedback: ZXCVBNFeedbackWarning): string => {
	switch (feedback) {
		case "":
			return ""
		case "Straight rows of keys are easy to guess":
			return "Sequências retas de teclas são fáceis de adivinhar"
		case "Short keyboard patterns are easy to guess":
			return "Padrões curtos de teclado são fáceis de adivinhar"
		case "Use a longer keyboard pattern with more turns":
			return "Use um padrão de teclado mais longo e com mais variações"
		case 'Repeats like "aaa" are easy to guess':
			return "Repetições como 'aaa' são fáceis de adivinhar"
		case 'Repeats like "abcabcabc" are only slightly harder to guess than "abc"':
			return "Repetições como 'abcabcabc' são apenas um pouco mais difíceis de adivinhar do que 'abc'"
		case "Sequences like abc or 6543 are easy to guess":
			return "Sequências como abc ou 6543 são fáceis de adivinhar"
		case "Recent years are easy to guess":
			return "Anos recentes são fáceis de adivinhar"
		case "Dates are often easy to guess":
			return "Datas frequentemente são fáceis de adivinhar"
		case "This is a top-10 common password":
			return "Esta é uma das 10 senhas mais comuns"
		case "This is a top-100 common password":
			return "Esta é uma das 100 senhas mais comuns"
		case "This is a very common password":
			return "Esta é uma senha muito comum"
		case "This is similar to a commonly used password":
			return "Esta senha é similar a uma senha comumente usada"
		case "A word by itself is easy to guess":
			return "Uma palavra sozinha é fácil de adivinhar"
		case "Names and surnames by themselves are easy to guess":
			return "Nomes e sobrenomes sozinhos são fáceis de adivinhar"
		case "Common names and surnames are easy to guess":
			return "Nomes e sobrenomes comuns são fáceis de adivinhar"
		default:
			return feedback || ""
	}
}
