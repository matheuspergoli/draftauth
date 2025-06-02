/**
 * Use this to connect authentication providers that support OAuth 2.0.
 *
 * ```ts {5-12}
 * import { Oauth2Provider } from "@draftauth/core/provider/oauth2"
 *
 * export default issuer({
 *   providers: {
 *     oauth2: Oauth2Provider({
 *       clientID: "1234567890",
 *       clientSecret: "0987654321",
 *       endpoint: {
 *         authorization: "https://auth.myserver.com/authorize",
 *         token: "https://auth.myserver.com/token"
 *       }
 *     })
 *   }
 * })
 * ```
 *
 *
 * @packageDocumentation
 */
import type { Context } from "hono"
import { createRemoteJWKSet, jwtVerify } from "jose"
import { OauthError, type OauthErrorType } from "../error"
import { generatePKCE } from "../pkce"
import { getRelativeUrl } from "../util"
import type { Provider } from "./provider"

export interface Oauth2Config {
	/**
	 * @internal
	 */
	type?: string
	/**
	 * The client ID.
	 *
	 * This is just a string to identify your app.
	 *
	 * @example
	 * ```ts
	 * {
	 *   clientID: "my-client"
	 * }
	 * ```
	 */
	clientID: string
	/**
	 * The client secret.
	 *
	 * This is a private key that's used to authenticate your app. It should be kept secret.
	 *
	 * @example
	 * ```ts
	 * {
	 *   clientSecret: "0987654321"
	 * }
	 * ```
	 */
	clientSecret: string
	/**
	 * The URLs of the authorization and token endpoints.
	 *
	 * @example
	 * ```ts
	 * {
	 *   endpoint: {
	 *     authorization: "https://auth.myserver.com/authorize",
	 *     token: "https://auth.myserver.com/token",
	 *     jwks: "https://auth.myserver.com/auth/keys"
	 *   }
	 * }
	 * ```
	 */
	endpoint: {
		/**
		 * The URL of the authorization endpoint.
		 */
		authorization: string
		/**
		 * The URL of the token endpoint.
		 */
		token: string
		/**
		 * The URL of the JWKS endpoint.
		 */
		jwks?: string
	}
	/**
	 * A list of OAuth scopes that you want to request.
	 *
	 * @example
	 * ```ts
	 * {
	 *   scopes: ["email", "profile"]
	 * }
	 * ```
	 */
	scopes: string[]
	/**
	 * Whether to use PKCE (Proof Key for Code Exchange) for the authorization code flow.
	 * Some providers like x.com require this.
	 * @default false
	 */
	pkce?: boolean
	/**
	 * Any additional parameters that you want to pass to the authorization endpoint.
	 * @example
	 * ```ts
	 * {
	 *   query: {
	 *     access_type: "offline",
	 *     prompt: "consent"
	 *   }
	 * }
	 * ```
	 */
	query?: Record<string, string>
}

/**
 * @internal
 */
export type Oauth2WrappedConfig = Omit<Oauth2Config, "endpoint" | "name">

/**
 * @internal
 */
export interface Oauth2Token {
	access: string
	refresh: string
	expiry: number
	id: Record<string, unknown> | null
	raw: Record<string, unknown>
}

interface ProviderState {
	state: string
	redirect: string
	codeVerifier?: string
}

interface TokenResponse {
	access_token: string
	refresh_token?: string
	expires_in?: number
	id_token?: string
	error?: string
	error_description?: string
	[key: string]: unknown
}

export const Oauth2Provider = (
	config: Oauth2Config
): Provider<{ tokenset: Oauth2Token; clientID: string }> => {
	const query = config.query || {}

	const handleCallbackLogic = async (
		c: Context,
		ctx: {
			get: <T>(c: Context, key: string) => Promise<T | undefined>
			set: <T>(c: Context, key: string, ttl: number, value: T) => Promise<void>
			success: (
				c: Context,
				data: { tokenset: Oauth2Token; clientID: string }
			) => Promise<Response>
		},
		provider: ProviderState,
		code: string | undefined
	): Promise<Response> => {
		if (!provider || !code) {
			return c.redirect(getRelativeUrl(c, "./authorize"))
		}

		const body = new URLSearchParams({
			client_id: config.clientID,
			client_secret: config.clientSecret,
			code,
			grant_type: "authorization_code",
			redirect_uri: provider.redirect,
			...(provider.codeVerifier ? { code_verifier: provider.codeVerifier } : {})
		})

		const response = await fetch(config.endpoint.token, {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
				Accept: "application/json"
			},
			body: body.toString()
		})

		const json = (await response.json()) as TokenResponse

		if (json.error) {
			throw new OauthError(json.error as OauthErrorType, json.error_description || "")
		}

		let idTokenPayload: Record<string, unknown> | null = null
		if (config.endpoint.jwks && json.id_token) {
			const jwksEndpoint = new URL(config.endpoint.jwks)
			const jwks = createRemoteJWKSet(jwksEndpoint)
			const { payload } = await jwtVerify(json.id_token, jwks, {
				audience: config.clientID
			})
			idTokenPayload = payload
		}

		return await ctx.success(c, {
			clientID: config.clientID,
			tokenset: {
				get access(): string {
					return json.access_token
				},
				get refresh(): string {
					return json.refresh_token || ""
				},
				get expiry(): number {
					return json.expires_in || 0
				},
				get id(): Record<string, unknown> | null {
					return idTokenPayload
				},
				get raw(): Record<string, unknown> {
					return json
				}
			}
		})
	}

	return {
		type: config.type || "oauth2",
		init(routes, ctx) {
			routes.get("/authorize", async (c: Context) => {
				const state = crypto.randomUUID()
				const pkce = config.pkce ? await generatePKCE() : undefined
				await ctx.set<ProviderState>(c, "provider", 60 * 10, {
					state,
					redirect: getRelativeUrl(c, "./callback"),
					codeVerifier: pkce?.verifier
				})
				const authorization = new URL(config.endpoint.authorization)
				authorization.searchParams.set("client_id", config.clientID)
				authorization.searchParams.set("redirect_uri", getRelativeUrl(c, "./callback"))
				authorization.searchParams.set("response_type", "code")
				authorization.searchParams.set("state", state)
				authorization.searchParams.set("scope", config.scopes.join(" "))
				if (pkce) {
					authorization.searchParams.set("code_challenge", pkce.challenge)
					authorization.searchParams.set("code_challenge_method", pkce.method)
				}
				for (const [key, value] of Object.entries(query)) {
					authorization.searchParams.set(key, value)
				}
				return c.redirect(authorization.toString())
			})

			routes.get("/callback", async (c: Context) => {
				const provider = (await ctx.get(c, "provider")) as ProviderState
				const code = c.req.query("code")
				const state = c.req.query("state")
				const error = c.req.query("error")

				if (error) {
					throw new OauthError(error as OauthErrorType, c.req.query("error_description") || "")
				}
				if (!provider || !code || (provider.state && state !== provider.state)) {
					return c.redirect(getRelativeUrl(c, "./authorize"))
				}

				return await handleCallbackLogic(c, ctx, provider, code)
			})

			routes.post("/callback", async (c: Context) => {
				const provider = (await ctx.get(c, "provider")) as ProviderState

				const formData = await c.req.formData()
				const code = formData.get("code")?.toString()
				const state = formData.get("state")?.toString()
				const error = formData.get("error")?.toString()

				if (error) {
					throw new OauthError(
						error as OauthErrorType,
						formData.get("error_description")?.toString() || ""
					)
				}

				if (!provider || !code || (provider.state && state !== provider.state)) {
					return c.redirect(getRelativeUrl(c, "./authorize"))
				}

				return await handleCallbackLogic(c, ctx, provider, code)
			})
		}
	}
}
