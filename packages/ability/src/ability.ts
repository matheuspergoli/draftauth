import { evaluateCondition } from "./evaluator"
import type {
	AbilitySubject,
	ActionName,
	Conditions,
	Fields,
	RegisteredSubjectTypeName,
	Rule,
	SubjectObject,
	SubjectObjectBase,
	SubjectTypeMappings
} from "./types"
import { actionsMatcher, detectSubjectTypeName, subjectsMatcher } from "./utils"

export class Ability<AppActions extends ActionName, AppSubjects extends SubjectTypeMappings> {
	private rulesList: Rule<AppActions, AppSubjects>[]

	constructor(rules: Rule<AppActions, AppSubjects>[] = []) {
		this.rulesList = rules
	}

	addRule(rule: Rule<AppActions, AppSubjects>): void {
		this.rulesList.push(rule)
	}

	can<Name extends RegisteredSubjectTypeName<AppSubjects>>(
		action: AppActions,
		subject: AbilitySubject<Name, AppSubjects>,
		field?: Fields<Name, AppSubjects>
	): boolean {
		const subjectNameFromDetection = detectSubjectTypeName<AppSubjects>(subject)
		const subjectInstance =
			typeof subject === "string" ? undefined : (subject as SubjectObject<Name, AppSubjects>)

		let relevantCanRuleExists = false
		for (const rule of this.rulesList) {
			if (
				!actionsMatcher(action, rule.action) ||
				!subjectsMatcher(subjectNameFromDetection, rule.subject)
			) {
				continue
			}

			let conditionsApply = true
			if (rule.conditions && Object.keys(rule.conditions).length > 0) {
				if (rule.subject === "all") {
					conditionsApply = this.checkGlobalConditions(
						rule.conditions as Record<string, unknown>,
						subjectInstance
					)
				} else {
					conditionsApply = this.checkTypedConditions<Name>(
						rule.conditions as Conditions<Name, AppSubjects>,
						subjectInstance
					)
				}
			}

			const fieldsApply =
				rule.subject === "all"
					? this.checkGlobalFields(
							rule.fields as string[] | undefined,
							field as string | undefined
						)
					: this.checkTypedFields(
							rule.fields as Fields<Name, AppSubjects>[] | undefined,
							field
						)

			if (conditionsApply && fieldsApply) {
				if (rule.inverted) {
					return false
				}
				relevantCanRuleExists = true
			}
		}
		return relevantCanRuleExists
	}

	cannot<Name extends RegisteredSubjectTypeName<AppSubjects>>(
		action: AppActions,
		subject: AbilitySubject<Name, AppSubjects>,
		field?: Fields<Name, AppSubjects>
	): boolean {
		return !this.can(action, subject, field)
	}

	private checkGlobalConditions(
		conditions: Record<string, unknown> | undefined,
		subjectInstance?: SubjectObjectBase
	): boolean {
		if (!conditions || Object.keys(conditions).length === 0) return true
		if (!subjectInstance) return false

		for (const key of Object.keys(conditions)) {
			const expected = conditions[key]!
			const actual = subjectInstance[key as keyof SubjectObjectBase]

			if (!evaluateCondition(actual, expected)) {
				return false
			}
		}

		return true
	}

	private checkTypedConditions<Name extends RegisteredSubjectTypeName<AppSubjects>>(
		conditions: Conditions<Name, AppSubjects> | undefined,
		subjectInstance?: SubjectObject<Name, AppSubjects>
	): boolean {
		if (!conditions || Object.keys(conditions).length === 0) {
			return true
		}
		if (!subjectInstance) {
			return false
		}

		for (const key in conditions) {
			if (!Object.prototype.hasOwnProperty.call(conditions, key)) {
				continue
			}
			const conditionKey = key as keyof Conditions<Name, AppSubjects>

			if (conditionKey === "$and") {
				const subConditionsArray = conditions[conditionKey] as Conditions<Name, AppSubjects>[]
				if (!Array.isArray(subConditionsArray)) return false
				for (const subCondition of subConditionsArray) {
					if (!this.checkTypedConditions(subCondition, subjectInstance)) {
						return false
					}
				}
				continue
			}

			if (conditionKey === "$or") {
				const subConditionsArray = conditions[conditionKey] as Conditions<Name, AppSubjects>[]
				if (!Array.isArray(subConditionsArray) || subConditionsArray.length === 0) return false
				let orPassed = false
				for (const subCondition of subConditionsArray) {
					if (this.checkTypedConditions(subCondition, subjectInstance)) {
						orPassed = true
						break
					}
				}
				if (!orPassed) return false
				continue
			}

			if (conditionKey === "$not") {
				const subCondition = conditions[conditionKey] as Conditions<Name, AppSubjects>
				if (this.checkTypedConditions(subCondition, subjectInstance)) {
					return false
				}
				continue
			}

			const fieldName = key as Fields<Name, AppSubjects>
			const node = conditions[fieldName]!
			const subjectValue = subjectInstance[fieldName]

			if (!evaluateCondition(subjectValue, node)) {
				return false
			}
		}
		return true
	}

	private checkGlobalFields(
		ruleFields: string[] | undefined,
		requestedField?: string
	): boolean {
		if (!requestedField) return true
		if (!ruleFields || ruleFields.length === 0) return true
		return ruleFields.includes(requestedField)
	}

	private checkTypedFields<Name extends RegisteredSubjectTypeName<AppSubjects>>(
		ruleFields: Fields<Name, AppSubjects>[] | undefined,
		requestedField?: Fields<Name, AppSubjects>
	): boolean {
		if (!requestedField) return true
		if (!ruleFields || ruleFields.length === 0) return true
		return ruleFields.includes(requestedField)
	}
}
