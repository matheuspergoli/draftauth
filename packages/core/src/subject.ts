/**
 * Subjects define the structure of data stored in access tokens after successful authentication.
 * They represent the different types of entities that can be authenticated (users, admins, etc.)
 * and are encoded as JWT claims in the resulting access tokens.
 *
 * ## Quick Start
 *
 * ### 1. Define your subjects
 * ```ts title="subjects.ts"
 * import { object, string } from "valibot"
 * import { createSubjects } from "@draftauth/core/subject"
 *
 * export const subjects = createSubjects({
 *   user: object({
 *     userID: string()
 *   }),
 *   admin: object({
 *     userID: string(),
 *     workspaceID: string()
 *   })
 * })
 * ```
 *
 * ### 2. Use in your issuer
 * ```ts title="issuer.ts"
 * import { subjects } from "./subjects"
 *
 * const app = issuer({
 *   providers: { github: GithubProvider({...}) },
 *   subjects,
 *   async success(ctx, value) {
 *     const userID = await lookupUser(value.email)
 *     return ctx.subject("user", { userID })
 *   }
 * })
 * ```
 *
 * ### 3. Verify tokens in your app
 * ```ts title="middleware.ts"
 * import { subjects } from "./subjects"
 *
 * const verified = await client.verify(subjects, accessToken)
 * console.log(verified.subject.properties.userID) // Fully typed!
 * ```
 *
 * ## Important Notes
 *
 * - Only store data that doesn't change frequently (avoid usernames, emails that might change)
 * - Keep payload small as it's embedded in every access token
 * - Use any validation library compatible with standard-schema specification
 *
 * @packageDocumentation
 */
import type { StandardSchemaV1 } from "@standard-schema/spec"
import type { Prettify } from "./util"

/**
 * Schema definition for subjects, mapping subject type names to their validation schemas.
 * Each key represents a subject type, and each value is a schema that validates
 * the properties for that subject type.
 *
 * @example
 * ```ts
 * const schema: SubjectSchema = {
 *   user: object({ userID: string() }),
 *   admin: object({ userID: string(), workspaceID: string() })
 * }
 * ```
 */
export type SubjectSchema = Record<string, StandardSchemaV1>

/**
 * Internal type that transforms a SubjectSchema into a union of subject payload objects.
 * Each payload contains the subject type and its validated properties.
 *
 * @template T - The subject schema to transform
 * @internal
 */
export type SubjectPayload<T extends SubjectSchema> = Prettify<
	{
		[K in keyof T & string]: {
			type: K
			properties: StandardSchemaV1.InferOutput<T[K]>
		}
	}[keyof T & string]
>

/**
 * Creates a strongly-typed subject schema that can be used throughout your application.
 * The returned schema maintains type information for excellent IDE support and runtime validation.
 *
 * @template Schema - The subject schema type being created
 * @param types - Object mapping subject type names to their validation schemas
 * @returns The same schema object with preserved type information
 *
 * @example
 * ```ts
 * import { object, string, number } from "valibot"
 *
 * const subjects = createSubjects({
 *   user: object({
 *     userID: string(),
 *     createdAt: number()
 *   }),
 *   admin: object({
 *     userID: string(),
 *     workspaceID: string(),
 *     permissions: array(string())
 *   }),
 *   service: object({
 *     serviceID: string(),
 *     apiVersion: string()
 *   })
 * })
 *
 * // Now subjects is fully typed and can be used for:
 * // - Type checking in success callbacks
 * // - Token verification with proper type inference
 * // - IDE autocompletion for subject types and properties
 * ```
 */
export const createSubjects = <Schema extends SubjectSchema>(types: Schema): Schema => {
	return { ...types }
}
