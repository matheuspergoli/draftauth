export type AppNameActions =
	| "access_admin_panel"
	| "view_application"
	| "create_application"
	| "delete_application"
	| "create_redirect_uri"
	| "delete_redirect_uri"
	| "create_api_key"
	| "delete_api_key"
	| "create_role"
	| "edit_role"
	| "delete_role"
	| "view_user"
	| "assign_role_to_user"
	| "revoke_role_from_user"
	| "edit_user_global_status"
	| "edit_user_application_access"

export type AppSubjectTypeMappings = {
	User: { _subjectType: "User" }
	AdminPanel: { _subjectType: "AdminPanel" }
	Application: { _subjectType: "Application" }
}

export const SYSTEM_ROLES = {
	SUPER_ADMIN_ROLE: "SUPER_ADMIN",
	APPLICATION_ADMINISTRATOR_ROLE: "APPLICATION_ADMINISTRATOR"
}
