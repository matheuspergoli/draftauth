import type {
	AbilitySubject,
	ActionName,
	ConditionOperators,
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

		for (const key in conditions) {
			if (Object.prototype.hasOwnProperty.call(conditions, key)) {
				const expected = conditions[key]
				const actual = subjectInstance[key as keyof SubjectObjectBase]

				if (typeof expected === "object" && expected !== null && !Array.isArray(expected)) {
					const expectedAsRecord = expected as Record<string, unknown>
					if (expectedAsRecord.$eq !== undefined && actual !== expectedAsRecord.$eq)
						return false
				} else if (actual !== expected) {
					return false
				}
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

			const fieldName = conditionKey as Fields<Name, AppSubjects>
			const conditionValueNode = conditions[fieldName] as Conditions<Name, AppSubjects>[Fields<
				Name,
				AppSubjects
			>]
			if (!this.evaluateFieldCondition(fieldName, conditionValueNode, subjectInstance)) {
				return false
			}
		}
		return true
	}

	private evaluateFieldCondition<Name extends RegisteredSubjectTypeName<AppSubjects>>(
		fieldName: Fields<Name, AppSubjects>,
		conditionValueNode: Conditions<Name, AppSubjects>[Fields<Name, AppSubjects>],
		subjectInstance: SubjectObject<Name, AppSubjects>
	): boolean {
		const subjectValue = subjectInstance[fieldName]

		if (
			typeof conditionValueNode === "object" &&
			conditionValueNode !== null &&
			!Array.isArray(conditionValueNode)
		) {
			const operatorObject = conditionValueNode as ConditionOperators<typeof subjectValue>
			for (const opKey in operatorObject) {
				if (Object.prototype.hasOwnProperty.call(operatorObject, opKey)) {
					const op = opKey as keyof typeof operatorObject
					const opValue = operatorObject[op]
					let opFailed = false

					switch (op) {
						case "$eq":
							if (subjectValue !== opValue) opFailed = true
							break
						case "$ne":
							if (subjectValue === opValue) opFailed = true
							break
						case "$in":
							if (!Array.isArray(opValue)) {
								opFailed = true
								break
							}
							if (Array.isArray(subjectValue)) {
								if (
									!(subjectValue as unknown[]).some((item) =>
										(opValue as unknown[]).includes(item)
									)
								) {
									opFailed = true
								}
							} else {
								if (!(opValue as unknown[]).includes(subjectValue)) {
									opFailed = true
								}
							}
							break
						case "$nin":
							if (!Array.isArray(opValue)) {
								opFailed = true
								break
							}
							if (Array.isArray(subjectValue)) {
								if (
									(subjectValue as unknown[]).some((item) =>
										(opValue as unknown[]).includes(item)
									)
								) {
									opFailed = true
								}
							} else {
								if ((opValue as unknown[]).includes(subjectValue)) {
									opFailed = true
								}
							}
							break
						case "$lt":
						case "$lte":
						case "$gt":
						case "$gte":
							if (subjectValue === null || typeof subjectValue === "undefined") {
								if (subjectValue === opValue && (op === "$lte" || op === "$gte")) {
								} else {
									opFailed = true
								}
							} else if (opValue === null || typeof opValue === "undefined") {
								opFailed = true
							} else if (typeof subjectValue !== typeof opValue) {
								opFailed = true
							} else {
								if (op === "$lt" && !(subjectValue < opValue)) opFailed = true
								if (op === "$lte" && !(subjectValue <= opValue)) opFailed = true
								if (op === "$gt" && !(subjectValue > opValue)) opFailed = true
								if (op === "$gte" && !(subjectValue >= opValue)) opFailed = true
							}
							break
						case "$exists": {
							if (typeof opValue === "boolean") {
								const propActuallyExists =
									Object.prototype.hasOwnProperty.call(subjectInstance, fieldName) &&
									subjectInstance[fieldName] !== undefined

								if (opValue === true && !propActuallyExists) opFailed = true
								if (opValue === false && propActuallyExists) opFailed = true
							} else {
								opFailed = true
							}
							break
						}
						default:
							opFailed = true
					}
					if (opFailed) {
						return false
					}
				}
			}
			return true
		}
		return subjectValue === conditionValueNode
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
