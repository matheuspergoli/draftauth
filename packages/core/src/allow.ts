import { isDomainMatch } from "./util"

/**
 * @interface AllowCheckInput
 * @description Input parameters for the allow check function.
 */
export interface AllowCheckInput {
	/**
	 * @property The client ID of the application requesting authorization.
	 */
	clientID: string
	/**
	 * @property The redirect URI to which the user will be sent after authorization.
	 */
	redirectURI: string
	/**
	 * @property The optional audience parameter for the authorization request.
	 */
	audience?: string
}

/**
 * @function defaultAllowCheck
 * @async
 * @description Default logic to determine if a client's authorization request is permitted.
 * It checks if the `redirectURI` is localhost or if its hostname matches
 * the request's hostname (or `x-forwarded-host`) at the same effective TLD+1 level.
 * @param {AllowCheckInput} input - The details of the client request, including clientID and redirectURI.
 * @param {Request} req - The original Fetch API Request object.
 * @returns {Promise<boolean>} True if the request is allowed, false otherwise.
 */
export const defaultAllowCheck = async (
	input: AllowCheckInput,
	req: Request
): Promise<boolean> => {
	let redirHostname: string
	try {
		redirHostname = new URL(input.redirectURI).hostname
	} catch (e) {
		console.error("Invalid redirectURI format in allow check:", input.redirectURI, e)
		return false
	}

	if (redirHostname === "localhost" || redirHostname === "127.0.0.1") {
		return true
	}

	let currentHost: string
	try {
		const forwardedHost = req.headers.get("x-forwarded-host")
		currentHost = forwardedHost
			? new URL(`https://${forwardedHost}`).hostname
			: new URL(req.url).hostname
	} catch (e) {
		console.error("Could not determine current host in allow check:", req.url, e)
		return false
	}

	return isDomainMatch(redirHostname, currentHost)
}
