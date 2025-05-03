import React from "react"

import { cn } from "@/libs/utils"
import { createFormHook, createFormHookContexts, useStore } from "@tanstack/react-form"
import { Button } from "./button"
import { Input } from "./input"
import { Label } from "./label"
import {
	Select,
	SelectContent,
	SelectGroup,
	SelectItem,
	SelectLabel,
	SelectTrigger,
	SelectValue
} from "./select"
import { Textarea } from "./textarea"

export const { fieldContext, useFieldContext, formContext, useFormContext } =
	createFormHookContexts()

type ErrorMessagesProps = React.ComponentProps<"p">
function ErrorMessages(props: ErrorMessagesProps) {
	const field = useFieldContext()
	const errors = useStore(field.store, (state) => state.meta.errors)

	return (
		<>
			{field.state.meta.isTouched
				? errors.map((error) => (
						<div
							key={typeof error === "string" ? error : error.message}
							className="text-red-500"
							{...props}
						>
							{typeof error === "string" ? error : error.message}
						</div>
					))
				: null}
		</>
	)
}

type FieldsetProps = React.ComponentProps<"fieldset">
export function Fieldset(props: FieldsetProps) {
	const childrenArray = React.Children.toArray(props.children)

	const errorMessages = childrenArray.filter((child) => {
		return React.isValidElement(child) && child.type === ErrorMessages
	})

	const otherFields = childrenArray.filter((child) => {
		return !(React.isValidElement(child) && child.type === ErrorMessages)
	})

	return (
		<>
			<fieldset {...props}>
				<div className="space-y-1">{otherFields}</div>
				{errorMessages.length ? errorMessages : null}
			</fieldset>
		</>
	)
}

type SubscribeButtonProps = React.ComponentProps<"button">
export function SubscribeButton(props: SubscribeButtonProps) {
	const form = useFormContext()

	return (
		<form.Subscribe selector={(state) => state.isSubmitting}>
			{(isSubmitting) => (
				<Button
					{...props}
					className={cn(props.className)}
					type="submit"
					mode="loading"
					isLoading={isSubmitting}
					disabled={isSubmitting}
				/>
			)}
		</form.Subscribe>
	)
}

type TextFieldProps = React.ComponentProps<"input">
export function TextField(props: TextFieldProps) {
	const field = useFieldContext<string>()

	return (
		<Input
			{...props}
			id={field.name}
			name={field.name}
			value={field.state.value}
			onBlur={field.handleBlur}
			onChange={(e) => field.handleChange(e.target.value)}
		/>
	)
}

type SelectFieldProps = React.ComponentProps<"select"> & {
	placeholder?: string
	label: string
	values: { label: string; value: string }[]
}
export function SelectField(props: SelectFieldProps) {
	const field = useFieldContext<string>()

	return (
		<Select
			name={field.name}
			value={field.state.value}
			onValueChange={(value) => field.handleChange(value)}
		>
			<SelectTrigger className="w-full">
				<SelectValue placeholder={props?.placeholder} />
			</SelectTrigger>
			<SelectContent>
				<SelectGroup>
					<SelectLabel>{props.label}</SelectLabel>
					{props.values.map((value) => (
						<SelectItem key={value.value} value={value.value}>
							{value.label}
						</SelectItem>
					))}
				</SelectGroup>
			</SelectContent>
		</Select>
	)
}

type LabelFieldProps = React.ComponentProps<"label">
export function LabelField(props: LabelFieldProps) {
	const field = useFieldContext()

	return <Label {...props} htmlFor={field.name} />
}

type TextAreaFieldProps = React.ComponentProps<"textarea">
export function TextArea(props: TextAreaFieldProps) {
	const field = useFieldContext<string>()

	return (
		<Textarea
			{...props}
			value={field.state.value}
			onBlur={field.handleBlur}
			onChange={(e) => field.handleChange(e.target.value)}
		/>
	)
}

export const { useAppForm } = createFormHook({
	fieldComponents: {
		TextArea,
		Fieldset,
		TextField,
		LabelField,
		SelectField,
		ErrorMessages
	},
	formComponents: {
		SubscribeButton
	},
	fieldContext,
	formContext
})
