import type { ConditionOperators } from "./types"

type Operator = keyof ConditionOperators<unknown>

export type OperatorHandler<TSubjectValue, KOp extends Operator> = (
	subjectValue: TSubjectValue,
	operatorValue: ConditionOperators<TSubjectValue>[KOp]
) => boolean

export interface HandlersMap {
	$eq: OperatorHandler<unknown, "$eq">
	$ne: OperatorHandler<unknown, "$ne">
	$lt: OperatorHandler<unknown, "$lt">
	$lte: OperatorHandler<unknown, "$lte">
	$gt: OperatorHandler<unknown, "$gt">
	$gte: OperatorHandler<unknown, "$gte">
	$in: OperatorHandler<unknown, "$in">
	$nin: OperatorHandler<unknown, "$nin">
	$all: OperatorHandler<unknown, "$all">
	$exists: OperatorHandler<unknown | undefined, "$exists">
}

export const HANDLERS: HandlersMap = {
	$eq: <T>(a: T, b: T | undefined) => a === b,
	$ne: <T>(a: T, b: T | undefined) => a !== b,
	$lt: <T>(a: T, b: T | undefined): boolean => {
		if (a === null || typeof a === "undefined") return false
		if (b === null || typeof b === "undefined") return false
		if (typeof a !== typeof b) return false
		return a < b
	},
	$lte: <T>(a: T, b: T | undefined): boolean => {
		if (a === null || typeof a === "undefined") return a === b
		if (b === null || typeof b === "undefined") return false
		if (typeof a !== typeof b) return false
		return a <= b
	},
	$gt: <T>(a: T, b: T | undefined): boolean => {
		if (a === null || typeof a === "undefined") return false
		if (b === null || typeof b === "undefined") return false
		if (typeof a !== typeof b) return false
		return a > b
	},
	$gte: <T>(a: T, b: T | undefined): boolean => {
		if (a === null || typeof a === "undefined") return a === b
		if (b === null || typeof b === "undefined") return false
		if (typeof a !== typeof b) return false
		return a >= b
	},
	$in: <TSubjectValue>(
		subjectValue: TSubjectValue,
		conditionValues: ConditionOperators<TSubjectValue>["$in"]
	) => {
		if (!Array.isArray(conditionValues)) return false
		if (Array.isArray(subjectValue)) {
			return subjectValue.some((item) => conditionValues.includes(item))
		}
		return conditionValues.includes(subjectValue)
	},
	$nin: <TSubjectValue>(
		subjectValue: TSubjectValue,
		conditionValues: ConditionOperators<TSubjectValue>["$nin"]
	) => {
		if (!Array.isArray(conditionValues)) return false
		if (Array.isArray(subjectValue)) {
			return !subjectValue.some((item) => conditionValues.includes(item))
		}
		return !conditionValues.includes(subjectValue)
	},
	$exists: <TSubjectValue>(
		subjectValue: TSubjectValue,
		flag: ConditionOperators<TSubjectValue>["$exists"]
	) => {
		if (typeof flag !== "boolean") return false
		const propActuallyExists = subjectValue !== undefined
		return flag === true ? propActuallyExists : !propActuallyExists
	},
	$all: (subjectValue, conditionValues) => {
		if (!Array.isArray(subjectValue) || !Array.isArray(conditionValues)) return false
		return conditionValues.every((item) => subjectValue.includes(item))
	}
}

const KNOWN_OPERATORS = new Set(Object.keys(HANDLERS))

export const evaluateCondition = <TFieldType>(
	subjectValue: TFieldType,
	conditionNode: TFieldType | ConditionOperators<TFieldType>
): boolean => {
	let isOperatorObjectNode = false
	if (
		typeof conditionNode === "object" &&
		conditionNode !== null &&
		!Array.isArray(conditionNode)
	) {
		const keys = Object.keys(conditionNode)
		if (keys.length > 0 && keys.every((key) => KNOWN_OPERATORS.has(key))) {
			isOperatorObjectNode = true
		}
	}

	if (isOperatorObjectNode) {
		const operatorNode = conditionNode as ConditionOperators<TFieldType>

		for (const opKey of Object.keys(operatorNode) as Array<
			keyof ConditionOperators<TFieldType>
		>) {
			let conditionPassed = false

			switch (opKey) {
				case "$eq":
					conditionPassed = HANDLERS.$eq(subjectValue, operatorNode[opKey])
					break
				case "$ne":
					conditionPassed = HANDLERS.$ne(subjectValue, operatorNode[opKey])
					break
				case "$lt":
					conditionPassed = HANDLERS.$lt(subjectValue, operatorNode[opKey])
					break
				case "$lte":
					conditionPassed = HANDLERS.$lte(subjectValue, operatorNode[opKey])
					break
				case "$gt":
					conditionPassed = HANDLERS.$gt(subjectValue, operatorNode[opKey])
					break
				case "$gte":
					conditionPassed = HANDLERS.$gte(subjectValue, operatorNode[opKey])
					break
				case "$in":
					conditionPassed = HANDLERS.$in(subjectValue, operatorNode[opKey])
					break
				case "$nin":
					conditionPassed = HANDLERS.$nin(subjectValue, operatorNode[opKey])
					break
				case "$exists":
					conditionPassed = HANDLERS.$exists(subjectValue, operatorNode[opKey])
					break
				case "$all":
					conditionPassed = HANDLERS.$all(subjectValue, operatorNode[opKey])
					break
				default:
					return false
			}

			if (!conditionPassed) return false
		}
		return true
	}
	return subjectValue === conditionNode
}
