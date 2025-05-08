PRAGMA foreign_keys=OFF;--> statement-breakpoint
CREATE TABLE `__new_audit_logs` (
	`log_id` text PRIMARY KEY NOT NULL,
	`timestamp` integer NOT NULL,
	`details` text,
	`event_type` text NOT NULL,
	`target_user_id` text,
	`target_app_id` text,
	`target_role_id` text,
	`target_api_key_id` text,
	FOREIGN KEY (`target_user_id`) REFERENCES `users`(`user_id`) ON UPDATE no action ON DELETE set null,
	FOREIGN KEY (`target_app_id`) REFERENCES `applications`(`app_id`) ON UPDATE no action ON DELETE set null,
	FOREIGN KEY (`target_role_id`) REFERENCES `roles`(`role_id`) ON UPDATE no action ON DELETE set null,
	FOREIGN KEY (`target_api_key_id`) REFERENCES `application_api_keys`(`key_id`) ON UPDATE no action ON DELETE set null
);
--> statement-breakpoint
INSERT INTO `__new_audit_logs`("log_id", "timestamp", "details", "event_type", "target_user_id", "target_app_id", "target_role_id", "target_api_key_id") SELECT "log_id", "timestamp", "details", "event_type", "target_user_id", "target_app_id", "target_role_id", "target_api_key_id" FROM `audit_logs`;--> statement-breakpoint
DROP TABLE `audit_logs`;--> statement-breakpoint
ALTER TABLE `__new_audit_logs` RENAME TO `audit_logs`;--> statement-breakpoint
PRAGMA foreign_keys=ON;