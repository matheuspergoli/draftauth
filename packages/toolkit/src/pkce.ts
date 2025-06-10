const base64urlEncode = (buffer: Uint8Array): string => {
	return btoa(String.fromCharCode(...buffer))
		.replace(/=/g, "")
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
}

const generateVerifier = (length: number): string => {
	const buffer = new Uint8Array(length)
	crypto.getRandomValues(buffer)
	return base64urlEncode(buffer)
}

const generateChallenge = async (verifier: string): Promise<string> => {
	const encoder = new TextEncoder()
	const data = encoder.encode(verifier)
	const hash = await crypto.subtle.digest("SHA-256", data)
	return base64urlEncode(new Uint8Array(hash))
}

export const generatePKCE = async (length = 64) => {
	if (length < 43 || length > 128) {
		throw new Error("PKCE verifier length must be between 43 and 128 characters.")
	}
	const verifier = generateVerifier(length)
	const challenge = await generateChallenge(verifier)
	return {
		verifier,
		challenge,
		method: "S256"
	}
}
