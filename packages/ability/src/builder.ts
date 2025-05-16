import { Ability } from "./ability"
import type {
	ActionName,
	Conditions,
	Fields,
	RegisteredSubjectTypeName,
	Rule,
	SubjectTypeMappings
} from "./types"

export class AbilityBuilder<
	AppActions extends ActionName,
	AppSubjects extends SubjectTypeMappings,
	ConcreteAbility extends Ability<AppActions, AppSubjects> = Ability<AppActions, AppSubjects>
> {
	public rules: Rule<AppActions, AppSubjects>[] = []

	private ResolvedAbilityClass: new (
		rules: Rule<AppActions, AppSubjects>[]
	) => ConcreteAbility

	constructor(
		AbilityClassParam: new (
			rules: Rule<AppActions, AppSubjects>[]
		) => ConcreteAbility = Ability as new (
			rules: Rule<AppActions, AppSubjects>[]
		) => ConcreteAbility
	) {
		this.ResolvedAbilityClass = AbilityClassParam
	}

	can<Name extends RegisteredSubjectTypeName<AppSubjects>>(
		action: AppActions | AppActions[],
		subject: Name | Name[]
	): this
	can(action: AppActions | AppActions[], subject: "all"): this

	can<Name extends RegisteredSubjectTypeName<AppSubjects>>(
		action: AppActions | AppActions[],
		subject: Name | Name[],
		conditions: Conditions<Name, AppSubjects>
	): this

	can<Name extends RegisteredSubjectTypeName<AppSubjects>>(
		action: AppActions | AppActions[],
		subject: Name | Name[],
		fields: Fields<Name, AppSubjects>[] | null
	): this

	can<Name extends RegisteredSubjectTypeName<AppSubjects>>(
		action: AppActions | AppActions[],
		subject: Name | Name[],
		fields: Fields<Name, AppSubjects>[] | null | undefined,
		conditions: Conditions<Name, AppSubjects>
	): this

	can(
		action: AppActions | AppActions[],
		subject: "all",
		conditions: Record<string, unknown>
	): this

	can(action: AppActions | AppActions[], subject: "all", fields: string[] | null): this

	can(
		action: AppActions | AppActions[],
		subject: "all",
		fields: string[] | null | undefined,
		conditions: Record<string, unknown>
	): this

	can<Name extends RegisteredSubjectTypeName<AppSubjects>>(
		action: AppActions | AppActions[],
		subject: Name | Name[] | "all",
		p3?:
			| string[]
			| Fields<Name, AppSubjects>[]
			| Conditions<Name, AppSubjects>
			| Record<string, unknown>
			| null,
		p4?: Conditions<Name, AppSubjects> | Record<string, unknown>
	): this {
		const ruleToAdd: Partial<Rule<AppActions, AppSubjects>> = {
			action,
			subject: subject,
			inverted: false
		}

		let finalRuleFields = undefined
		let finalRuleConditions = undefined

		if (p4 !== undefined) {
			finalRuleFields = p3
			finalRuleConditions = p4
		} else if (p3 !== null && p3 !== undefined) {
			if (Array.isArray(p3)) {
				finalRuleFields = p3
			} else if (typeof p3 === "object") {
				finalRuleConditions = p3
			}
		}

		if (finalRuleFields !== null && finalRuleFields !== undefined) {
			ruleToAdd.fields = finalRuleFields as Rule<AppActions, AppSubjects>["fields"]
		}
		if (finalRuleConditions !== undefined) {
			ruleToAdd.conditions = finalRuleConditions as Rule<AppActions, AppSubjects>["conditions"]
		}

		this.rules.push(ruleToAdd as Rule<AppActions, AppSubjects>)
		return this
	}

	cannot<Name extends RegisteredSubjectTypeName<AppSubjects>>(
		action: AppActions | AppActions[],
		subject: Name | Name[]
	): this
	cannot(action: AppActions | AppActions[], subject: "all"): this

	cannot<Name extends RegisteredSubjectTypeName<AppSubjects>>(
		action: AppActions | AppActions[],
		subject: Name | Name[],
		conditions: Conditions<Name, AppSubjects>
	): this

	cannot<Name extends RegisteredSubjectTypeName<AppSubjects>>(
		action: AppActions | AppActions[],
		subject: Name | Name[],
		fields: Fields<Name, AppSubjects>[] | null
	): this

	cannot<Name extends RegisteredSubjectTypeName<AppSubjects>>(
		action: AppActions | AppActions[],
		subject: Name | Name[],
		fields: Fields<Name, AppSubjects>[] | null | undefined,
		conditions: Conditions<Name, AppSubjects>
	): this

	cannot(
		action: AppActions | AppActions[],
		subject: "all",
		conditions: Record<string, unknown>
	): this

	cannot(action: AppActions | AppActions[], subject: "all", fields: string[] | null): this

	cannot(
		action: AppActions | AppActions[],
		subject: "all",
		fields: string[] | null | undefined,
		conditions: Record<string, unknown>
	): this

	cannot<Name extends RegisteredSubjectTypeName<AppSubjects>>(
		action: AppActions | AppActions[],
		subject: Name | Name[] | "all",
		p3?:
			| string[]
			| Fields<Name, AppSubjects>[]
			| Conditions<Name, AppSubjects>
			| Record<string, unknown>
			| null,
		p4?: Conditions<Name, AppSubjects> | Record<string, unknown>
	): this {
		const ruleToAdd: Partial<Rule<AppActions, AppSubjects>> = {
			action,
			subject: subject,
			inverted: true
		}

		let finalRuleFields = undefined
		let finalRuleConditions = undefined

		if (p4 !== undefined) {
			finalRuleFields = p3
			finalRuleConditions = p4
		} else if (p3 !== null && p3 !== undefined) {
			if (Array.isArray(p3)) {
				finalRuleFields = p3
			} else if (typeof p3 === "object") {
				finalRuleConditions = p3
			}
		}

		if (finalRuleFields !== null && finalRuleFields !== undefined) {
			ruleToAdd.fields = finalRuleFields as Rule<AppActions, AppSubjects>["fields"]
		}

		if (finalRuleConditions !== undefined) {
			ruleToAdd.conditions = finalRuleConditions as Rule<AppActions, AppSubjects>["conditions"]
		}

		this.rules.push(ruleToAdd as Rule<AppActions, AppSubjects>)
		return this
	}

	build(): ConcreteAbility {
		return new this.ResolvedAbilityClass(this.rules)
	}
}
