export const parseScopes = (scope: string | string[] | null | undefined) => {
	if (Array.isArray(scope)) {
		return scope.filter(Boolean)
	}
	return scope?.split(" ").filter(Boolean) ?? []
}

export const validateScopes = (tokenReq?: string | null, authorizeReq?: string[]) => {
	if (!authorizeReq?.length || tokenReq === null || tokenReq === undefined) {
		return authorizeReq
	}
	return [...new Set(parseScopes(tokenReq)).intersection(new Set(authorizeReq))]
}
