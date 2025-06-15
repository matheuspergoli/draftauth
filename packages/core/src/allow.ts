import { isDomainMatch } from "./util"

/**
 * Client authorization validation utilities.
 * Provides security checks to determine if OAuth authorization requests should be permitted
 * based on redirect URI validation and domain matching policies.
 */

/**
 * Input parameters for authorization allow checks.
 * Contains all necessary information to validate if a client request should be permitted.
 */
export interface AllowCheckInput {
	/** The client ID of the application requesting authorization */
	readonly clientID: string
	/** The redirect URI where the user will be sent after authorization */
	readonly redirectURI: string
	/** Optional audience parameter for the authorization request */
	readonly audience?: string
}

/**
 * Default authorization check that validates client requests based on redirect URI security.
 *
 * ## Security Policy
 * - **Localhost**: Always allowed (for development)
 * - **Same domain**: Redirect URI must match request origin at TLD+1 level
 * - **Cross-domain**: Rejected for security
 *
 * This prevents unauthorized applications from hijacking authorization codes by using
 * malicious redirect URIs that don't belong to the legitimate client application.
 *
 * @param input - Client request details including ID and redirect URI
 * @param req - The original HTTP request for domain comparison
 * @returns Promise resolving to true if the request should be allowed
 *
 * @example
 * ```ts
 * // Allowed: localhost development
 * await defaultAllowCheck({
 *   clientID: "dev-app",
 *   redirectURI: "http://localhost:3000/callback"
 * }, request) // → true
 *
 * // Allowed: same domain
 * // Request from: https://myapp.com
 * await defaultAllowCheck({
 *   clientID: "web-app",
 *   redirectURI: "https://auth.myapp.com/callback"
 * }, request) // → true
 *
 * // Rejected: different domain
 * // Request from: https://myapp.com
 * await defaultAllowCheck({
 *   clientID: "malicious-app",
 *   redirectURI: "https://evil.com/steal-codes"
 * }, request) // → false
 * ```
 */
export const defaultAllowCheck = async (
	input: AllowCheckInput,
	req: Request
): Promise<boolean> => {
	// Extract and validate redirect URI hostname
	let redirectHostname: string
	try {
		redirectHostname = new URL(input.redirectURI).hostname
	} catch (error) {
		return false
	}

	// Always allow localhost for development
	if (redirectHostname === "localhost" || redirectHostname === "127.0.0.1") {
		return true
	}

	// Extract current request hostname (handling proxy headers)
	let currentHostname: string
	try {
		const forwardedHost = req.headers.get("x-forwarded-host")
		currentHostname = forwardedHost
			? new URL(`https://${forwardedHost}`).hostname
			: new URL(req.url).hostname
	} catch (error) {
		return false
	}

	// Check if redirect URI belongs to the same effective domain
	return isDomainMatch(redirectHostname, currentHostname)
}
