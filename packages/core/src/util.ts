import type { Context } from "hono"

/**
 * Utility type that flattens complex types for better IntelliSense display.
 * Converts intersections and complex mapped types into cleaner object types.
 *
 * @template T - The type to prettify
 *
 * @example
 * ```ts
 * type Complex = { a: string } & { b: number }
 * type Clean = Prettify<Complex> // { a: string; b: number }
 * ```
 */
export type Prettify<T> = {
	[K in keyof T]: T[K]
} & {}

/**
 * Constructs a complete URL relative to the current request context.
 * Handles proxy headers (x-forwarded-*) to ensure correct URL generation
 * in containerized and load-balanced environments.
 *
 * @param ctx - Hono context containing request information
 * @param path - Relative path to append to the base URL
 * @returns Complete URL string with proper protocol, host, and port
 *
 * @example
 * ```ts
 * const callbackUrl = getRelativeUrl(ctx, "./callback")
 * // Returns: "https://myapp.com/auth/callback"
 * ```
 */
export const getRelativeUrl = (ctx: Context, path: string): string => {
	const result = new URL(path, ctx.req.url)
	result.host = ctx.req.header("x-forwarded-host") || result.host
	result.protocol = ctx.req.header("x-forwarded-proto") || result.protocol
	result.port = ctx.req.header("x-forwarded-port") || result.port
	return result.toString()
}

/**
 * List of known two-part top-level domains that require special handling
 * for domain matching. These domains have an additional level that should
 * be considered when determining effective domain boundaries.
 */
const twoPartTlds = [
	"co.uk",
	"co.jp",
	"co.kr",
	"co.nz",
	"co.za",
	"co.in",
	"com.au",
	"com.br",
	"com.cn",
	"com.mx",
	"com.tw",
	"net.au",
	"org.uk",
	"ne.jp",
	"ac.uk",
	"gov.uk",
	"edu.au",
	"gov.au"
] as const

/**
 * Determines if two domain names are considered a match for security purposes.
 * Uses effective TLD+1 matching to allow subdomains while preventing
 * unauthorized cross-domain requests.
 *
 * @param a - First domain name to compare
 * @param b - Second domain name to compare
 * @returns True if domains are considered a security match
 *
 * @example
 * ```ts
 * isDomainMatch("app.example.com", "auth.example.com") // true
 * isDomainMatch("example.com", "evil.com") // false
 * isDomainMatch("app.co.uk", "auth.co.uk") // true (handles two-part TLD)
 * ```
 */
export const isDomainMatch = (a: string, b: string): boolean => {
	if (a === b) return true

	const partsA = a.split(".")
	const partsB = b.split(".")

	const hasTwoPartTld = twoPartTlds.some(
		(tld) => a.endsWith(`.${tld}`) || b.endsWith(`.${tld}`)
	)

	const numParts = hasTwoPartTld ? -3 : -2
	const tailA = partsA.slice(numParts).join(".")
	const tailB = partsB.slice(numParts).join(".")

	return tailA === tailB
}

/**
 * Creates a lazy-evaluated function that caches the result of the first execution.
 * Subsequent calls return the cached value without re-executing the function.
 *
 * @template T - The return type of the lazy function
 * @param fn - Function to execute lazily
 * @returns Function that returns the cached result
 *
 * @example
 * ```ts
 * const expensiveOperation = lazy(() => {
 *   // Computing... (only logs once)
 *   return heavyComputation()
 * })
 *
 * const result1 = expensiveOperation() // Executes and caches
 * const result2 = expensiveOperation() // Returns cached value
 * ```
 */
export const lazy = <T>(fn: () => T): (() => T) => {
	let hasValue = false
	let value: T

	return (): T => {
		if (!hasValue) {
			value = fn()
			hasValue = true
		}
		return value
	}
}
