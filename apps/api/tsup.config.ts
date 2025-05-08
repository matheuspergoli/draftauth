import { defineConfig } from "tsup"

export default defineConfig((options) => ({
	entry: ["src/index.ts"],
	format: ["esm"],
	target: "esnext",
	dts: false,
	clean: true,
	minify: true,
	treeshake: true,
	splitting: true,
	sourcemap: false,
	...options
}))
