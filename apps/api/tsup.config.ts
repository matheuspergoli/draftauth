import { defineConfig } from "tsup"

export default defineConfig((options) => ({
	entry: ["src/index.ts"],
	format: ["esm"],
	target: "esnext",
	dts: false,
	splitting: true,
	sourcemap: false,
	clean: true,
	minify: true,
	treeshake: true,
	...options
}))
