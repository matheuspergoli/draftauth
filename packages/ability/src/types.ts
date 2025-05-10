export type SubjectTypeName = string

export type ActionName = string

export interface SubjectObjectBase {
	_subjectType?: SubjectTypeName
}

export type SubjectTypeMappings = {
	[K in SubjectTypeName]: SubjectObjectBase
}

export type RegisteredSubjectTypeName<Subjects extends SubjectTypeMappings> = Extract<
	keyof Subjects,
	SubjectTypeName
>

export type SubjectObject<
	Name extends RegisteredSubjectTypeName<Subjects>,
	Subjects extends SubjectTypeMappings
> = Subjects[Name]

export type AbilitySubject<
	Name extends RegisteredSubjectTypeName<Subjects>,
	Subjects extends SubjectTypeMappings
> = Name | SubjectObject<Name, Subjects>

export type Fields<
	Name extends RegisteredSubjectTypeName<Subjects>,
	Subjects extends SubjectTypeMappings
> = Extract<keyof SubjectObject<Name, Subjects>, string>

export type ConditionOperators<T> = {
	$eq?: T
	$ne?: T
	$in?: T[]
	$nin?: T[]
	$lt?: T
	$lte?: T
	$gt?: T
	$gte?: T
	$exists?: boolean
}

export type Conditions<
	Name extends RegisteredSubjectTypeName<Subjects>,
	Subjects extends SubjectTypeMappings
> = {
	[P in Fields<Name, Subjects>]?:
		| SubjectObject<Name, Subjects>[P]
		| ConditionOperators<SubjectObject<Name, Subjects>[P]>
} & {
	$and?: Conditions<Name, Subjects>[]
	$or?: Conditions<Name, Subjects>[]
	$not?: Conditions<Name, Subjects>
}

export interface Rule<Actions extends ActionName, Subjects extends SubjectTypeMappings> {
	action: Actions | Actions[]
	subject: RegisteredSubjectTypeName<Subjects> | RegisteredSubjectTypeName<Subjects>[] | "all"
	inverted?: boolean
	conditions?: this["subject"] extends "all"
		? Record<string, unknown>
		: this["subject"] extends RegisteredSubjectTypeName<Subjects>
			? Conditions<Extract<this["subject"], RegisteredSubjectTypeName<Subjects>>, Subjects>
			: Partial<{
					[SubjectNameKey in RegisteredSubjectTypeName<Subjects>]: Conditions<
						SubjectNameKey,
						Subjects
					>
				}>
	fields?: this["subject"] extends "all"
		? string[]
		: this["subject"] extends RegisteredSubjectTypeName<Subjects>
			? Fields<Extract<this["subject"], RegisteredSubjectTypeName<Subjects>>, Subjects>[]
			: string[]
	reason?: string
}
