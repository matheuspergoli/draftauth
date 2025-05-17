import type {
	ActionName,
	RegisteredSubjectTypeName,
	SubjectObjectBase,
	SubjectTypeMappings,
	SubjectTypeName
} from "./types"

export const detectSubjectTypeName = <Subjects extends SubjectTypeMappings>(
	subject: SubjectTypeName | SubjectObjectBase
): RegisteredSubjectTypeName<Subjects> | SubjectTypeName => {
	if (typeof subject === "string") return subject
	if (subject && typeof subject === "object") {
		if (subject._subjectType) {
			return subject._subjectType as RegisteredSubjectTypeName<Subjects>
		}
		return subject.constructor.name as RegisteredSubjectTypeName<Subjects>
	}
	throw new Error(`Cannot detect subject type for ${JSON.stringify(subject)}`)
}

export const actionsMatcher = (
	requestedActions: ActionName | ActionName[],
	ruleActions: ActionName | ActionName[]
): boolean => {
	const requested = Array.isArray(requestedActions) ? requestedActions : [requestedActions]
	const rule = Array.isArray(ruleActions) ? ruleActions : [ruleActions]
	if (rule.includes("manage")) return true
	return requested.some((action) => rule.includes(action))
}

export const subjectsMatcher = <Subjects extends SubjectTypeMappings>(
	requestedSubjectName: RegisteredSubjectTypeName<Subjects> | SubjectTypeName,
	ruleSubjects:
		| RegisteredSubjectTypeName<Subjects>
		| RegisteredSubjectTypeName<Subjects>[]
		| "all"
): boolean => {
	if (ruleSubjects === "all") return true
	const rule = Array.isArray(ruleSubjects) ? ruleSubjects : [ruleSubjects]
	return rule.includes(requestedSubjectName as RegisteredSubjectTypeName<Subjects>)
}
