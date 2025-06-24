/**
 * Form alert component for displaying success and error messages.
 * Provides consistent styling and iconography for user feedback in authentication forms.
 *
 * ## Usage
 *
 * ```tsx
 * // Error message
 * <FormAlert
 *   message="Invalid email address"
 *   color="danger"
 * />
 *
 * // Success message
 * <FormAlert
 *   message="Code sent to your email"
 *   color="success"
 * />
 *
 * // Default (danger) message
 * <FormAlert message="Something went wrong" />
 * ```
 *
 * ## Features
 *
 * - **Visual feedback**: Clear success and error states with appropriate colors
 * - **Iconography**: Contextual icons for different message types
 * - **Accessibility**: Proper semantic markup and ARIA attributes
 * - **Responsive**: Adapts to different screen sizes
 * - **Themeable**: Uses CSS custom properties for easy customization
 */

/** @jsxImportSource hono/jsx */

/**
 * Alert color variant determining the visual style and icon.
 */
export type FormAlertColor = "danger" | "success"

/**
 * Props for the FormAlert component.
 */
export interface FormAlertProps {
	/**
	 * The message text to display in the alert.
	 * If not provided, the alert will not render.
	 *
	 * @example
	 * ```tsx
	 * <FormAlert message="Password must be at least 8 characters" />
	 * ```
	 */
	readonly message?: string

	/**
	 * Visual style variant for the alert.
	 * Determines the color scheme and icon used.
	 *
	 * @default "danger"
	 *
	 * @example
	 * ```tsx
	 * <FormAlert message="Login successful" color="success" />
	 * <FormAlert message="Invalid credentials" color="danger" />
	 * ```
	 */
	readonly color?: FormAlertColor
}

/**
 * Form alert component for displaying contextual messages to users.
 * Shows success or error states with appropriate icons and styling.
 *
 * @param props - Alert configuration including message and color variant
 * @returns JSX element representing the styled alert, or null if no message
 *
 * @example
 * ```tsx
 * // In a login form
 * {loginError && (
 *   <FormAlert
 *     message="Invalid username or password"
 *     color="danger"
 *   />
 * )}
 *
 * // In a registration form
 * {emailSent && (
 *   <FormAlert
 *     message="Verification email sent to your inbox"
 *     color="success"
 *   />
 * )}
 *
 * // With conditional rendering
 * <FormAlert
 *   message={error?.message}
 *   color={error?.type === 'success' ? 'success' : 'danger'}
 * />
 * ```
 */
export const FormAlert = (props: FormAlertProps) => {
	// Don't render if no message is provided
	if (!props.message) return null

	const alertColor = props.color ?? "danger"

	return (
		<div aria-live="polite" data-color={alertColor} data-component="form-alert" role="alert">
			{/* Success icon - checkmark in circle */}
			<SuccessIcon />

			{/* Danger/Error icon - exclamation in circle */}
			<DangerIcon />

			{/* Alert message text */}
			<span data-slot="message">{props.message}</span>
		</div>
	)
}

/**
 * Success icon component showing a checkmark in a circle.
 * Used for positive feedback messages.
 */
const SuccessIcon = () => (
	<svg
		aria-hidden="true"
		data-slot="icon-success"
		fill="none"
		stroke="currentColor"
		strokeWidth="1.5"
		viewBox="0 0 24 24"
		xmlns="http://www.w3.org/2000/svg"
	>
		<path
			d="M9 12.75 11.25 15 15 9.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z"
			strokeLinecap="round"
			strokeLinejoin="round"
		/>
	</svg>
)

/**
 * Danger icon component showing an exclamation mark in a circle.
 * Used for error and warning messages.
 */
const DangerIcon = () => (
	<svg
		aria-hidden="true"
		data-slot="icon-danger"
		fill="none"
		stroke="currentColor"
		strokeWidth="1.5"
		viewBox="0 0 24 24"
		xmlns="http://www.w3.org/2000/svg"
	>
		<path
			d="M12 9v3.75m9-.75a9 9 0 1 1-18 0 9 9 0 0 1 18 0Zm-9 3.75h.008v.008H12v-.008Z"
			strokeLinecap="round"
			strokeLinejoin="round"
		/>
	</svg>
)
