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

			const conditionsApply =
				rule.subject === "all" || !subjectInstance
					? this.checkGlobalConditions(
							rule.conditions as Record<string, unknown> | undefined,
							subjectInstance
						)
					: this.checkTypedConditions(
							rule.conditions as Conditions<Name, AppSubjects> | undefined,
							subjectInstance as SubjectObject<Name, AppSubjects>
						)

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
		if (!conditions) return true
		if (!subjectInstance) return Object.keys(conditions).length === 0

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
		if (!conditions) return true
		if (!subjectInstance) return Object.keys(conditions).length === 0

		for (const key in conditions) {
			if (Object.prototype.hasOwnProperty.call(conditions, key)) {
				const k = key as Fields<Name, AppSubjects>
				const conditionValueNode = conditions[k as keyof typeof conditions]
				const subjectValue = subjectInstance[k]

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

							switch (op) {
								case "$eq": {
									if (subjectValue !== opValue) return false
									break
								}
								case "$ne": {
									if (subjectValue === opValue) return false
									break
								}
								case "$in": {
									if (
										!Array.isArray(opValue) ||
										(opValue as unknown[]).indexOf(subjectValue) === -1
									) {
										return false
									}
									break
								}
								case "$nin": {
									if (
										Array.isArray(opValue) &&
										(opValue as unknown[]).indexOf(subjectValue) !== -1
									) {
										return false
									}
									break
								}
								case "$lt":
								case "$lte":
								case "$gt":
								case "$gte": {
									if (opValue === null || opValue === undefined) {
										return false
									}

									if (op === "$lt" && !(subjectValue < opValue)) return false
									if (op === "$lte" && !(subjectValue <= opValue)) return false
									if (op === "$gt" && !(subjectValue > opValue)) return false
									if (op === "$gte" && !(subjectValue >= opValue)) return false
									break
								}
								case "$exists": {
									if (typeof opValue === "boolean") {
										const propActuallyExists =
											k in subjectInstance && subjectInstance[k] !== undefined
										if (opValue === true && !propActuallyExists) return false
										if (opValue === false && propActuallyExists) return false
									} else {
										return false
									}
									break
								}
								default:
									return false
							}
						}
					}
				} else {
					if (subjectValue !== conditionValueNode) {
						return false
					}
				}
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
