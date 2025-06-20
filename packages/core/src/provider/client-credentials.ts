/**
 * Client Credentials provider for machine-to-machine authentication.
 * Enables direct service authentication using client_id and client_secret.
 *
 * ## Quick Setup
 *
 * ```ts
 * import { ClientCredentialsProvider } from "@draftauth/core/provider/client-credentials"
 *
 * export default issuer({
 *   providers: {
 *     "client-credentials": ClientCredentialsProvider({
 *       verify: async ({ clientID, clientSecret, scopes }) => {
 *         // Validate client credentials
 *         const client = await getClientFromDatabase(clientID, clientSecret)
 *         if (!client) return null
 *
 *         // Validate scopes
 *         const allowedScopes = scopes.filter(scope =>
 *           client.permissions.includes(scope)
 *         )
 *
 *         return {
 *           serviceId: client.id,
 *           serviceName: client.name,
 *           scopes: allowedScopes,
 *           tenantId: client.tenantId
 *         }
 *       }
 *     })
 *   }
 * })
 * ```
 *
 * @packageDocumentation
 */

import type { Provider } from "./provider"

/**
 * Client credentials verification function parameters.
 */
export interface ClientCredentialsVerifyInput {
	/** OAuth 2.0 client identifier */
	clientID: string
	/** OAuth 2.0 client secret */
	clientSecret: string
	/** Requested OAuth 2.0 scopes */
	scopes: string[]
	/** Additional parameters from the token request */
	params: Record<string, string>
}

/**
 * Configuration for the client credentials provider.
 */
export interface ClientCredentialsConfig<TResult = Record<string, unknown>> {
	/**
	 * Function to verify client credentials and return service data.
	 * Return null to reject the authentication attempt.
	 *
	 * @param input - Client credentials and request parameters
	 * @returns Service data for the authenticated client, or null if invalid
	 *
	 * @example
	 * ```ts
	 * verify: async ({ clientID, clientSecret, scopes }) => {
	 *   // Query your database/service registry
	 *   const client = await db.clients.findOne({
	 *     id: clientID,
	 *     secret: await hashSecret(clientSecret),
	 *     active: true
	 *   })
	 *
	 *   if (!client) return null
	 *
	 *   // Filter scopes based on client permissions
	 *   const allowedScopes = scopes.filter(scope =>
	 *     client.allowedScopes.includes(scope)
	 *   )
	 *
	 *   return {
	 *     serviceId: client.id,
	 *     serviceName: client.name,
	 *     permissions: allowedScopes,
	 *     tenantId: client.tenantId,
	 *     environment: client.environment
	 *   }
	 * }
	 * ```
	 */
	verify: (input: ClientCredentialsVerifyInput) => Promise<TResult | null>
}

/**
 * Service data returned by successful client credentials authentication.
 */
export interface ClientCredentialsResult<T = Record<string, unknown>> {
	/** Service/client properties returned by the verify function */
	readonly service: T
}

/**
 * Creates a Client Credentials authentication provider.
 * This provider enables machine-to-machine authentication using OAuth 2.0 client credentials flow.
 *
 * @param config - Client credentials provider configuration
 * @returns Provider instance implementing client credentials authentication
 *
 * @example
 * ```ts
 * // Database-backed client verification
 * const clientCredentials = ClientCredentialsProvider({
 *   verify: async ({ clientID, clientSecret, scopes, params }) => {
 *     // Verify against your client registry
 *     const client = await clientRegistry.authenticate(clientID, clientSecret)
 *     if (!client || !client.active) return null
 *
 *     // Check tenant isolation if needed
 *     const tenantId = params.tenant_id
 *     if (tenantId && client.tenantId !== tenantId) return null
 *
 *     // Filter scopes based on client permissions
 *     const grantedScopes = scopes.filter(scope =>
 *       client.scopes.includes(scope)
 *     )
 *
 *     return {
 *       clientId: client.id,
 *       clientName: client.name,
 *       scopes: grantedScopes,
 *       tenantId: client.tenantId,
 *       environment: client.environment
 *     }
 *   }
 * })
 *
 * // Use in issuer
 * export default issuer({
 *   providers: {
 *     "client-credentials": clientCredentials
 *   },
 *   subjects: createSubjects({
 *     service: object({
 *       clientId: string(),
 *       clientName: string(),
 *       scopes: array(string()),
 *       tenantId: string(),
 *       environment: string()
 *     })
 *   }),
 *   success: async (ctx, result) => {
 *     if (result.provider === "client-credentials") {
 *       return ctx.subject("service", result.service)
 *     }
 *   }
 * })
 * ```
 */
export const ClientCredentialsProvider = <TResult = Record<string, unknown>>(
	config: ClientCredentialsConfig<TResult>
): Provider<ClientCredentialsResult<TResult>> => {
	return {
		type: "client-credentials",

		init() {
			// Client credentials flow doesn't need authorization routes
			// All logic is handled in the client() method below
		},

		// This is the key method for client_credentials flow
		client: async ({ clientID, clientSecret, params }) => {
			// Parse requested scopes
			const scopes = params.scope ? params.scope.split(" ").filter(Boolean) : []

			// Call the user-provided verification function
			const result = await config.verify({
				clientID,
				clientSecret,
				scopes,
				params
			})

			// Return null if verification failed
			if (result === null) {
				throw new Error("Invalid client credentials")
			}

			// Return the service data
			return {
				service: result
			}
		}
	}
}
