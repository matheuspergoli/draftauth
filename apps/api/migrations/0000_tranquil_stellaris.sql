CREATE TABLE `application_api_keys` (
	`key_id` text PRIMARY KEY NOT NULL,
	`app_id` text NOT NULL,
	`encrypted_secret_key` text NOT NULL,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`app_id`) REFERENCES `applications`(`app_id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `application_redirect_uris` (
	`uri_id` text PRIMARY KEY NOT NULL,
	`app_id` text NOT NULL,
	`uri` text NOT NULL,
	FOREIGN KEY (`app_id`) REFERENCES `applications`(`app_id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `app_redirect_uris_app_id_uri_idx` ON `application_redirect_uris` (`app_id`,`uri`);--> statement-breakpoint
CREATE TABLE `applications` (
	`app_id` text PRIMARY KEY NOT NULL,
	`app_name` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `audit_logs` (
	`log_id` text PRIMARY KEY NOT NULL,
	`timestamp` integer NOT NULL,
	`details` text,
	`event_type` text NOT NULL,
	`actor_user_id` text,
	`actor_ip_address` text,
	`target_user_id` text,
	`target_app_id` text,
	`target_role_id` text,
	`target_api_key_id` text,
	FOREIGN KEY (`actor_user_id`) REFERENCES `users`(`user_id`) ON UPDATE no action ON DELETE set null,
	FOREIGN KEY (`target_user_id`) REFERENCES `users`(`user_id`) ON UPDATE no action ON DELETE set null,
	FOREIGN KEY (`target_app_id`) REFERENCES `applications`(`app_id`) ON UPDATE no action ON DELETE set null,
	FOREIGN KEY (`target_role_id`) REFERENCES `roles`(`role_id`) ON UPDATE no action ON DELETE set null,
	FOREIGN KEY (`target_api_key_id`) REFERENCES `application_api_keys`(`key_id`) ON UPDATE no action ON DELETE set null
);
--> statement-breakpoint
CREATE TABLE `roles` (
	`role_id` text PRIMARY KEY NOT NULL,
	`role_name` text NOT NULL,
	`app_id` text NOT NULL,
	FOREIGN KEY (`app_id`) REFERENCES `applications`(`app_id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `app_id_role_name_idx` ON `roles` (`app_id`,`role_name`);--> statement-breakpoint
CREATE TABLE `system_configuration` (
	`config_key` text PRIMARY KEY NOT NULL,
	`config_value` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `user_application_access` (
	`user_access_id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`app_id` text NOT NULL,
	`access_status` text DEFAULT 'enabled' NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`user_id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`app_id`) REFERENCES `applications`(`app_id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `user_application_access_user_id_app_id_idx` ON `user_application_access` (`user_id`,`app_id`);--> statement-breakpoint
CREATE TABLE `user_external_identities` (
	`identity_id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`provider_name` text NOT NULL,
	`provider_user_id` text NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`user_id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `user_external_identities_provider_name_id_idx` ON `user_external_identities` (`provider_name`,`provider_user_id`);--> statement-breakpoint
CREATE TABLE `user_roles` (
	`user_role_id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`role_id` text NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`user_id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`role_id`) REFERENCES `roles`(`role_id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `user_roles_user_id_role_id_idx` ON `user_roles` (`user_id`,`role_id`);--> statement-breakpoint
CREATE TABLE `users` (
	`user_id` text PRIMARY KEY NOT NULL,
	`email` text NOT NULL,
	`status` text DEFAULT 'active' NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `users_email_unique` ON `users` (`email`);
