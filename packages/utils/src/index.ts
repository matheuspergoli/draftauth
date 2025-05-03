export const getBaseUrl = () => {
	if (typeof window !== "undefined") return window.location.origin
	if (process.env.VERCEL_URL) return `https://${process.env.VERCEL_URL}`
	if (process.env.RENDER_EXTERNAL_URL) return process.env.RENDER_EXTERNAL_URL
	if (process.env.KOYEB_PUBLIC_DOMAIN) return `https://${process.env.KOYEB_PUBLIC_DOMAIN}`
	if (process.env.RAILWAY_PUBLIC_DOMAIN) return `https://${process.env.RAILWAY_PUBLIC_DOMAIN}`

	return `http://localhost:${process.env.PORT ?? 3000}`
}
