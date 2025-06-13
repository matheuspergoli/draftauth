import type { Context, Hono } from "hono"
/**
 * Discovery endpoints handler for Draft Auth issuer.
 * Handles OAuth 2.0 and OIDC discovery endpoints for client configuration.
 */
import { cors } from "hono/cors"
import type { KeyPair } from "../keys"

/**
 * OIDC discovery document structure.
 * Follows OpenID Connect Discovery 1.0 specification.
 */
interface OidcDiscoveryDocument {
	/** Issuer identifier */
	issuer: string
	/** Authorization endpoint URL */
	authorization_endpoint: string
	/** Token endpoint URL */
	token_endpoint: string
	/** UserInfo endpoint URL */
	userinfo_endpoint: string
	/** JWKS endpoint URL */
	jwks_uri: string
	/** End session (logout) endpoint URL */
	end_session_endpoint: string
	/** Token revocation endpoint URL */
	revocation_endpoint: string
	/** Supported OAuth 2.0 response types */
	response_types_supported: string[]
	/** Supported OAuth 2.0 response modes */
	response_modes_supported: string[]
	/** Supported OAuth 2.0 grant types */
	grant_types_supported: string[]
	/** Supported subject types */
	subject_types_supported: string[]
	/** Supported ID token signing algorithms */
	id_token_signing_alg_values_supported: string[]
	/** Supported OAuth 2.0 scopes */
	scopes_supported: string[]
	/** Supported OIDC claims */
	claims_supported: string[]
	/** Supported token endpoint authentication methods */
	token_endpoint_auth_methods_supported: string[]
	/** Whether claims parameter is supported */
	claims_parameter_supported: boolean
	/** Whether request parameter is supported */
	request_parameter_supported: boolean
	/** Whether request_uri parameter is supported */
	request_uri_parameter_supported: boolean
	/** Whether request_uri registration is required */
	require_request_uri_registration: boolean
}

/**
 * OAuth 2.0 Authorization Server Metadata structure.
 */
interface OAuth2DiscoveryDocument {
	/** Issuer identifier */
	issuer: string
	/** Authorization endpoint URL */
	authorization_endpoint: string
	/** Token endpoint URL */
	token_endpoint: string
	/** Token revocation endpoint URL */
	revocation_endpoint: string
	/** JWKS endpoint URL */
	jwks_uri: string
	/** Supported OAuth 2.0 response types */
	response_types_supported: string[]
	/** Supported OAuth 2.0 scopes */
	scopes_supported: string[]
	/** Supported revocation endpoint authentication methods */
	revocation_endpoint_auth_methods_supported: string[]
}

/**
 * JWKS (JSON Web Key Set) document structure.
 * Contains public keys for JWT signature verification.
 */
interface JwksDocument {
	/** Array of JSON Web Keys */
	keys: Array<{
		/** Key algorithm */
		alg: string
		/** Key expiration time (seconds since epoch) */
		exp?: number
		/** Additional JWK properties */
		[key: string]: unknown
	}>
}

/**
 * Discovery handler dependencies provided by the issuer.
 */
interface DiscoveryDependencies {
	/** Function to get all signing keys */
	allSigning: () => Promise<KeyPair[]>
	/** Function to resolve issuer URL from context */
	issuer: (ctx: Context) => string
	/** Array of all supported OAuth 2.0 scopes */
	allSupportedScopes: string[]
	/** Array of all supported OIDC claims */
	claimsSupported: string[]
}

/**
 * Registers OAuth 2.0 and OIDC discovery endpoints with the Hono application.
 * Provides standardized metadata endpoints for client auto-configuration.
 *
 * @param app - Hono application instance
 * @param dependencies - Discovery handler dependencies
 */
export const registerDiscoveryEndpoints = <T>(
	app: Hono<{ Variables: { authorization: T } }>,
	dependencies: DiscoveryDependencies
): void => {
	const { allSigning, issuer, allSupportedScopes, claimsSupported } = dependencies

	/**
	 * JWKS (JSON Web Key Set) endpoint.
	 * Returns public keys for JWT signature verification.
	 *
	 * Standard endpoint: /.well-known/jwks.json
	 */
	app.get(
		"/.well-known/jwks.json",
		cors({
			origin: "*",
			allowHeaders: ["*"],
			allowMethods: ["GET"],
			credentials: false
		}),
		async (c) => {
			const signingKeys = await allSigning()

			const jwksDocument: JwksDocument = {
				keys: signingKeys.map((keyInfo) => ({
					...keyInfo.jwk,
					alg: keyInfo.alg,
					exp: keyInfo.expired ? Math.floor(keyInfo.expired.getTime() / 1000) : undefined
				}))
			}

			return c.json(jwksDocument)
		}
	)

	/**
	 * OIDC Discovery endpoint.
	 * Returns OpenID Connect configuration metadata.
	 *
	 * Standard endpoint: /.well-known/openid-configuration
	 * Specification: OpenID Connect Discovery 1.0
	 */
	app.get(
		"/.well-known/openid-configuration",
		cors({
			origin: "*",
			allowHeaders: ["*"],
			allowMethods: ["GET"],
			credentials: false
		}),
		async (c) => {
			const iss = issuer(c)

			const oidcDocument: OidcDiscoveryDocument = {
				issuer: iss,
				authorization_endpoint: `${iss}/authorize`,
				token_endpoint: `${iss}/token`,
				userinfo_endpoint: `${iss}/userinfo`,
				jwks_uri: `${iss}/.well-known/jwks.json`,
				end_session_endpoint: `${iss}/logout`,
				revocation_endpoint: `${iss}/revoke`,
				response_types_supported: [
					"code",
					"token",
					"id_token",
					"code id_token",
					"code token",
					"id_token token",
					"code id_token token"
				],
				response_modes_supported: ["query", "fragment"],
				grant_types_supported: ["authorization_code", "refresh_token"],
				subject_types_supported: ["public"],
				id_token_signing_alg_values_supported: ["RS256"],
				scopes_supported: allSupportedScopes,
				claims_supported: claimsSupported,
				token_endpoint_auth_methods_supported: ["none"],
				claims_parameter_supported: false,
				request_parameter_supported: false,
				request_uri_parameter_supported: false,
				require_request_uri_registration: false
			}

			return c.json(oidcDocument)
		}
	)

	/**
	 * OAuth 2.0 Authorization Server Metadata endpoint.
	 * Returns OAuth 2.0 server configuration metadata.
	 *
	 * Standard endpoint: /.well-known/oauth-authorization-server
	 */
	app.get(
		"/.well-known/oauth-authorization-server",
		cors({
			origin: "*",
			allowHeaders: ["*"],
			allowMethods: ["GET"],
			credentials: false
		}),
		async (c) => {
			const iss = issuer(c)

			const oauth2Document: OAuth2DiscoveryDocument = {
				issuer: iss,
				authorization_endpoint: `${iss}/authorize`,
				token_endpoint: `${iss}/token`,
				revocation_endpoint: `${iss}/revoke`,
				jwks_uri: `${iss}/.well-known/jwks.json`,
				response_types_supported: ["code", "token"],
				scopes_supported: allSupportedScopes,
				revocation_endpoint_auth_methods_supported: ["none"]
			}

			return c.json(oauth2Document)
		}
	)
}
