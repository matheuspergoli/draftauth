/**
 * GitHub authentication provider for Draft Auth.
 * Implements OAuth 2.0 flow for authenticating users with their GitHub accounts.
 *
 * ## Quick Setup
 *
 * ```ts
 * import { GithubProvider } from "@draftauth/core/provider/github"
 *
 * export default issuer({
 *   providers: {
 *     github: GithubProvider({
 *       clientID: process.env.GITHUB_CLIENT_ID,
 *       clientSecret: process.env.GITHUB_CLIENT_SECRET,
 *       scopes: ["user:email", "read:user"]
 *     })
 *   }
 * })
 * ```
 *
 * ## GitHub App vs OAuth App
 *
 * This provider works with both GitHub OAuth Apps and GitHub Apps:
 *
 * ### OAuth App (Recommended for user authentication)
 * ```ts
 * GithubProvider({
 *   clientID: "your-oauth-app-client-id",
 *   clientSecret: "your-oauth-app-client-secret",
 *   scopes: ["user:email", "read:user"]
 * })
 * ```
 *
 * ### GitHub App (For organization-level integrations)
 * ```ts
 * GithubProvider({
 *   clientID: "your-github-app-client-id",
 *   clientSecret: "your-github-app-client-secret",
 *   scopes: ["user:email", "read:user", "repo"]
 * })
 * ```
 *
 * ## Common Scopes
 *
 * - `user:email` - Access user's email addresses
 * - `read:user` - Read user profile information
 * - `repo` - Access public and private repositories
 * - `public_repo` - Access public repositories only
 * - `read:org` - Read organization membership
 * - `gist` - Create and update gists
 *
 * ## User Data Access
 *
 * ```ts
 * success: async (ctx, value) => {
 *   if (value.provider === "github") {
 *     const accessToken = value.tokenset.access
 *
 *     // Fetch user information
 *     const userResponse = await fetch('https://api.github.com/user', {
 *       headers: { Authorization: `Bearer ${accessToken}` }
 *     })
 *     const user = await userResponse.json()
 *
 *     // Fetch user emails (requires user:email scope)
 *     const emailsResponse = await fetch('https://api.github.com/user/emails', {
 *       headers: { Authorization: `Bearer ${accessToken}` }
 *     })
 *     const emails = await emailsResponse.json()
 *
 *     // User info: `${user.login} (${user.name})`
 *     // Primary email: emails.find(e => e.primary)?.email
 *   }
 * }
 * ```
 *
 * @packageDocumentation
 */

import { Oauth2Provider, type Oauth2WrappedConfig } from "./oauth2"

/**
 * Configuration options for GitHub OAuth 2.0 provider.
 * Extends the base OAuth 2.0 configuration with GitHub-specific documentation.
 */
export interface GithubConfig extends Oauth2WrappedConfig {
	/**
	 * GitHub OAuth App client ID or GitHub App client ID.
	 * Found in your GitHub App settings or OAuth App settings.
	 *
	 * @example
	 * ```ts
	 * {
	 *   clientID: "Iv1.a629723000043722" // OAuth App
	 *   // or
	 *   clientID: "Iv23liAG5t7VwMkUsKTi" // GitHub App
	 * }
	 * ```
	 */
	readonly clientID: string

	/**
	 * GitHub OAuth App client secret or GitHub App client secret.
	 * Keep this secure and never expose it to client-side code.
	 *
	 * @example
	 * ```ts
	 * {
	 *   clientSecret: process.env.GITHUB_CLIENT_SECRET
	 * }
	 * ```
	 */
	readonly clientSecret: string

	/**
	 * GitHub OAuth scopes to request access for.
	 * Determines what data and actions your app can access.
	 *
	 * @example
	 * ```ts
	 * {
	 *   scopes: [
	 *     "user:email",    // Access user email addresses
	 *     "read:user",     // Read user profile info
	 *     "public_repo",   // Access public repositories
	 *     "read:org"       // Read organization membership
	 *   ]
	 * }
	 * ```
	 */
	readonly scopes: string[]

	/**
	 * Additional query parameters for GitHub OAuth authorization.
	 * Useful for GitHub-specific options like restricting to organizations.
	 *
	 * @example
	 * ```ts
	 * {
	 *   query: {
	 *     allow_signup: "false",      // Disable new account creation
	 *     login: "suggested-username" // Pre-fill username field
	 *   }
	 * }
	 * ```
	 */
	readonly query?: Record<string, string>
}

/**
 * Creates a GitHub OAuth 2.0 authentication provider.
 * Supports both GitHub OAuth Apps and GitHub Apps for user authentication.
 *
 * @param config - GitHub OAuth 2.0 configuration
 * @returns OAuth 2.0 provider configured for GitHub
 *
 * @example
 * ```ts
 * // Basic GitHub authentication
 * const basicGithub = GithubProvider({
 *   clientID: process.env.GITHUB_CLIENT_ID,
 *   clientSecret: process.env.GITHUB_CLIENT_SECRET
 * })
 *
 * // GitHub with specific scopes
 * const githubWithScopes = GithubProvider({
 *   clientID: process.env.GITHUB_CLIENT_ID,
 *   clientSecret: process.env.GITHUB_CLIENT_SECRET,
 *   scopes: [
 *     "user:email",
 *     "read:user",
 *     "public_repo",
 *     "read:org"
 *   ]
 * })
 *
 * // GitHub with custom authorization options
 * const restrictedGithub = GithubProvider({
 *   clientID: process.env.GITHUB_CLIENT_ID,
 *   clientSecret: process.env.GITHUB_CLIENT_SECRET,
 *   scopes: ["user:email", "read:user"],
 *   query: {
 *     allow_signup: "false" // Don't allow new GitHub account creation
 *   }
 * })
 *
 * // Using the access token to fetch data
 * export default issuer({
 *   providers: { github: githubWithScopes },
 *   success: async (ctx, value) => {
 *     if (value.provider === "github") {
 *       const token = value.tokenset.access
 *
 *       // Get user profile
 *       const userRes = await fetch('https://api.github.com/user', {
 *         headers: { Authorization: `Bearer ${token}` }
 *       })
 *       const user = await userRes.json()
 *
 *       // Get user repositories (if repo scope granted)
 *       const reposRes = await fetch('https://api.github.com/user/repos', {
 *         headers: { Authorization: `Bearer ${token}` }
 *       })
 *       const repos = await reposRes.json()
 *
 *       return ctx.subject("user", {
 *         githubId: user.id,
 *         username: user.login,
 *         email: user.email,
 *         name: user.name,
 *         repoCount: repos.length
 *       })
 *     }
 *   }
 * })
 * ```
 */
export const GithubProvider = (config: GithubConfig) => {
	return Oauth2Provider({
		...config,
		type: "github",
		endpoint: {
			authorization: "https://github.com/login/oauth/authorize",
			token: "https://github.com/login/oauth/access_token"
		}
	})
}
