import { array, number, object, optional, string } from "valibot"
/**
 * Subject schema creation and type inference tests
 */
import { describe, expect, it } from "vitest"
import { type SubjectSchema, createSubjects } from "../src/subject"

describe("Subject Functions", () => {
	describe("createSubjects", () => {
		it("should create subjects with proper type preservation", () => {
			const subjects = createSubjects({
				user: object({
					userID: string(),
					name: string()
				}),
				admin: object({
					userID: string(),
					workspaceID: string()
				})
			})

			expect(subjects).toEqual({
				user: expect.any(Object),
				admin: expect.any(Object)
			})
			expect(subjects.user).toBeDefined()
			expect(subjects.admin).toBeDefined()
		})

		it("should handle empty subjects schema", () => {
			const subjects = createSubjects({})
			expect(subjects).toEqual({})
		})

		it("should preserve original schema object properties", () => {
			const userSchema = object({
				userID: string(),
				email: string()
			})
			const adminSchema = object({
				userID: string(),
				permissions: array(string())
			})

			const subjects = createSubjects({
				user: userSchema,
				admin: adminSchema
			})

			expect(subjects.user).toBe(userSchema)
			expect(subjects.admin).toBe(adminSchema)
		})

		it("should handle complex schema structures", () => {
			const subjects = createSubjects({
				user: object({
					userID: string(),
					name: string(),
					email: string(),
					createdAt: number(),
					metadata: optional(
						object({
							preferences: object({
								theme: string(),
								language: string()
							}),
							profile: object({
								avatar: optional(string()),
								bio: optional(string())
							})
						})
					)
				}),
				service: object({
					serviceID: string(),
					apiVersion: string(),
					permissions: array(string()),
					rateLimits: object({
						requestsPerMinute: number(),
						burstLimit: number()
					})
				}),
				admin: object({
					userID: string(),
					workspaceID: string(),
					role: string(),
					permissions: array(string()),
					lastLogin: optional(number())
				})
			})

			expect(subjects).toHaveProperty("user")
			expect(subjects).toHaveProperty("service")
			expect(subjects).toHaveProperty("admin")
			expect(Object.keys(subjects)).toHaveLength(3)
		})

		it("should handle single subject schema", () => {
			const subjects = createSubjects({
				user: object({
					id: string()
				})
			})

			expect(subjects).toEqual({
				user: expect.any(Object)
			})
			expect(Object.keys(subjects)).toHaveLength(1)
		})

		it("should maintain reference equality for schema objects", () => {
			const originalUserSchema = object({
				userID: string(),
				name: string()
			})

			const subjects = createSubjects({
				user: originalUserSchema
			})

			// Should maintain the same reference, not create a new object
			expect(subjects.user).toBe(originalUserSchema)
		})
	})

	describe("Type System Integration", () => {
		it("should work with various valibot schema types", () => {
			const subjects = createSubjects({
				// Basic types
				simple: object({
					id: string(),
					count: number()
				}),
				// Optional fields
				withOptional: object({
					required: string(),
					optional: optional(string())
				}),
				// Arrays
				withArrays: object({
					items: array(string()),
					numbers: array(number())
				}),
				// Nested objects
				nested: object({
					user: object({
						name: string(),
						settings: object({
							theme: string(),
							notifications: object({
								email: string(),
								push: string()
							})
						})
					})
				})
			})

			expect(subjects.simple).toBeDefined()
			expect(subjects.withOptional).toBeDefined()
			expect(subjects.withArrays).toBeDefined()
			expect(subjects.nested).toBeDefined()
		})

		it("should handle schema validation correctly", () => {
			const subjects = createSubjects({
				user: object({
					userID: string(),
					email: string(),
					age: number()
				})
			})

			// Test that the schema can actually validate data
			const userSchema = subjects.user
			expect(userSchema).toBeDefined()

			// The schema should have the standard-schema interface
			expect(userSchema).toHaveProperty("~standard")
		})
	})

	describe("Integration Scenarios", () => {
		it("should handle typical OAuth/OIDC subject scenarios", () => {
			const subjects = createSubjects({
				// Standard user subject for OIDC
				user: object({
					sub: string(), // OIDC subject identifier
					email: string(),
					email_verified: optional(string()),
					name: optional(string()),
					picture: optional(string()),
					preferred_username: optional(string())
				}),
				// Service account for API access
				service: object({
					client_id: string(),
					service_name: string(),
					scopes: array(string()),
					api_version: string()
				}),
				// Administrative access
				admin: object({
					sub: string(),
					tenant_id: string(),
					roles: array(string()),
					permissions: array(string()),
					workspace_id: optional(string())
				})
			})

			expect(subjects.user).toBeDefined()
			expect(subjects.service).toBeDefined()
			expect(subjects.admin).toBeDefined()
		})

		it("should handle multi-tenant application subjects", () => {
			const subjects = createSubjects({
				// Tenant-scoped user
				user: object({
					userID: string(),
					tenantID: string(),
					role: string(),
					permissions: array(string())
				}),
				// Cross-tenant admin
				superAdmin: object({
					userID: string(),
					globalPermissions: array(string()),
					accessibleTenants: array(string())
				}),
				// Tenant-specific service
				tenantService: object({
					serviceID: string(),
					tenantID: string(),
					serviceType: string(),
					apiEndpoints: array(string())
				})
			})

			expect(Object.keys(subjects)).toHaveLength(3)
			expect(subjects.user).toBeDefined()
			expect(subjects.superAdmin).toBeDefined()
			expect(subjects.tenantService).toBeDefined()
		})

		it("should handle microservices authentication subjects", () => {
			const subjects = createSubjects({
				// User context
				user: object({
					userID: string(),
					sessionID: string(),
					authTime: number()
				}),
				// Service-to-service authentication
				service: object({
					serviceID: string(),
					serviceName: string(),
					version: string(),
					environment: string(),
					authorizedServices: array(string())
				}),
				// API gateway context
				gateway: object({
					gatewayID: string(),
					upstreamService: string(),
					rateLimitKey: string(),
					requestID: string()
				})
			})

			expect(subjects).toHaveProperty("user")
			expect(subjects).toHaveProperty("service")
			expect(subjects).toHaveProperty("gateway")
		})

		it("should handle enterprise SSO scenarios", () => {
			const subjects = createSubjects({
				// Employee authentication
				employee: object({
					employeeID: string(),
					department: string(),
					role: string(),
					manager: optional(string()),
					groups: array(string()),
					clearanceLevel: number()
				}),
				// External contractor
				contractor: object({
					contractorID: string(),
					company: string(),
					projectID: string(),
					expiresAt: number(),
					restrictedResources: array(string())
				}),
				// System integration
				integration: object({
					integrationID: string(),
					systemName: string(),
					dataAccessLevel: string(),
					allowedOperations: array(string()),
					ipWhitelist: array(string())
				})
			})

			expect(Object.keys(subjects)).toHaveLength(3)
			expect(subjects.employee).toBeDefined()
			expect(subjects.contractor).toBeDefined()
			expect(subjects.integration).toBeDefined()
		})
	})

	describe("Edge Cases", () => {
		it("should handle subjects with very long type names", () => {
			const longTypeName = `${"very".repeat(50)}LongSubjectTypeName`
			const subjects = createSubjects({
				[longTypeName]: object({
					id: string()
				})
			})

			expect(subjects[longTypeName]).toBeDefined()
		})

		it("should handle subjects with special characters in property names", () => {
			const subjects = createSubjects({
				user: object({
					"user-id": string(),
					email_address: string(),
					"display.name": string(),
					"auth:provider": string()
				})
			})

			expect(subjects.user).toBeDefined()
		})

		it("should handle deeply nested schema structures", () => {
			const subjects = createSubjects({
				complex: object({
					level1: object({
						level2: object({
							level3: object({
								level4: object({
									level5: object({
										deepValue: string()
									})
								})
							})
						})
					})
				})
			})

			expect(subjects.complex).toBeDefined()
		})

		it("should handle empty object schemas", () => {
			const subjects = createSubjects({
				empty: object({})
			})

			expect(subjects.empty).toBeDefined()
		})

		it("should handle schemas with all optional fields", () => {
			const subjects = createSubjects({
				allOptional: object({
					optionalString: optional(string()),
					optionalNumber: optional(number()),
					optionalArray: optional(array(string())),
					optionalObject: optional(
						object({
							nested: optional(string())
						})
					)
				})
			})

			expect(subjects.allOptional).toBeDefined()
		})
	})

	describe("Performance", () => {
		it("should handle large numbers of subject types efficiently", () => {
			const largeSubjects: Record<string, ReturnType<typeof object>> = {}

			// Create 100 different subject types
			for (let i = 0; i < 100; i++) {
				largeSubjects[`subject${i}`] = object({
					id: string(),
					type: string(),
					value: number()
				})
			}

			const start = Date.now()
			const subjects = createSubjects(largeSubjects)
			const duration = Date.now() - start

			expect(Object.keys(subjects)).toHaveLength(100)
			expect(duration).toBeLessThan(50) // Should be very fast
		})

		it("should handle schemas with many properties efficiently", () => {
			const manyPropsSchema: Record<string, ReturnType<typeof string>> = {}

			// Create schema with 50 properties
			for (let i = 0; i < 50; i++) {
				manyPropsSchema[`prop${i}`] = string()
			}

			const start = Date.now()
			const subjects = createSubjects({
				manyProps: object(manyPropsSchema)
			})
			const duration = Date.now() - start

			expect(subjects.manyProps).toBeDefined()
			expect(duration).toBeLessThan(50) // Should be very fast
		})
	})

	describe("Error Handling", () => {
		it("should handle invalid schema gracefully during runtime", () => {
			// Create subjects with valid structure but potentially invalid runtime behavior
			const subjects = createSubjects({
				user: object({
					id: string()
				})
			})

			// Should not throw during creation
			expect(subjects.user).toBeDefined()
			expect(typeof subjects.user).toBe("object")
		})

		it("should maintain schema integrity with frozen objects", () => {
			const frozenSchema = Object.freeze(
				object({
					id: string(),
					name: string()
				})
			)

			const subjects = createSubjects({
				user: frozenSchema
			})

			expect(subjects.user).toBe(frozenSchema)
		})
	})
})

describe("Type Inference Tests", () => {
	describe("SubjectPayload type", () => {
		it("should properly infer types from simple schemas", () => {
			const subjects = createSubjects({
				user: object({
					userID: string(),
					name: string()
				}),
				admin: object({
					userID: string(),
					permissions: array(string())
				})
			})

			// Verify the structure exists
			expect(subjects.user).toBeDefined()
			expect(subjects.admin).toBeDefined()
		})

		it("should handle optional properties in type inference", () => {
			const subjects = createSubjects({
				user: object({
					id: string(),
					name: optional(string()),
					metadata: optional(
						object({
							lastLogin: optional(number())
						})
					)
				})
			})

			expect(subjects.user).toBeDefined()
		})
	})

	describe("SubjectSchema type", () => {
		it("should accept valid schema definitions", () => {
			// Test that SubjectSchema type accepts various valid schemas
			const validSchema: SubjectSchema = {
				user: object({ id: string() }),
				admin: object({ id: string(), role: string() })
			}

			const subjects = createSubjects(validSchema)
			expect(subjects).toEqual(validSchema)
		})

		it("should work with complex nested schemas", () => {
			const complexSchema: SubjectSchema = {
				user: object({
					profile: object({
						personal: object({
							name: string(),
							age: number()
						}),
						preferences: object({
							theme: string(),
							notifications: array(string())
						})
					})
				})
			}

			const subjects = createSubjects(complexSchema)
			expect(subjects.user).toBe(complexSchema.user)
		})
	})
})
