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

	can(
		action: AppActions | AppActions[],
		subject: "all",
		fields?: string[] | null,
		conditions?: undefined
	): this

	can<Name extends RegisteredSubjectTypeName<AppSubjects>>(
		action: AppActions | AppActions[],
		subject: Name | Name[],
		fields?: Fields<Name, AppSubjects>[] | null,
		conditions?: Conditions<Name, AppSubjects>
	): this

	can<Name extends RegisteredSubjectTypeName<AppSubjects>>(
		action: AppActions | AppActions[],
		subject: Name | Name[] | "all",
		fields?: (string[] | Fields<Name, AppSubjects>[]) | null,
		conditions?: Conditions<Name, AppSubjects>
	): this {
		const ruleToAdd: Partial<Rule<AppActions, AppSubjects>> = {
			action,
			subject: subject as
				| RegisteredSubjectTypeName<AppSubjects>
				| RegisteredSubjectTypeName<AppSubjects>[]
				| "all",
			inverted: false
		}

		if (fields !== null && fields !== undefined) {
			ruleToAdd.fields = fields as Rule<AppActions, AppSubjects>["fields"]
		}

		if (conditions !== undefined) {
			ruleToAdd.conditions = conditions as Rule<AppActions, AppSubjects>["conditions"]
		}

		this.rules.push(ruleToAdd as Rule<AppActions, AppSubjects>)
		return this
	}

	cannot(
		action: AppActions | AppActions[],
		subject: "all",
		fields?: string[] | null,
		conditions?: undefined
	): this

	cannot<Name extends RegisteredSubjectTypeName<AppSubjects>>(
		action: AppActions | AppActions[],
		subject: Name | Name[],
		fields?: Fields<Name, AppSubjects>[] | null,
		conditions?: Conditions<Name, AppSubjects>
	): this

	cannot<Name extends RegisteredSubjectTypeName<AppSubjects>>(
		action: AppActions | AppActions[],
		subject: Name | Name[] | "all",
		fields?: (string[] | Fields<Name, AppSubjects>[]) | null,
		conditions?: Conditions<Name, AppSubjects>
	): this {
		const ruleToAdd: Partial<Rule<AppActions, AppSubjects>> = {
			action,
			subject: subject as
				| RegisteredSubjectTypeName<AppSubjects>
				| RegisteredSubjectTypeName<AppSubjects>[]
				| "all",
			inverted: true
		}

		if (fields !== null && fields !== undefined) {
			ruleToAdd.fields = fields as Rule<AppActions, AppSubjects>["fields"]
		}
		if (conditions !== undefined) {
			ruleToAdd.conditions = conditions as Rule<AppActions, AppSubjects>["conditions"]
		}

		this.rules.push(ruleToAdd as Rule<AppActions, AppSubjects>)
		return this
	}

	build(): ConcreteAbility {
		return new this.ResolvedAbilityClass(this.rules)
	}
}
