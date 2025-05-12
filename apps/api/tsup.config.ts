import { defineConfig } from "tsup"

export default defineConfig((options) => ({
	entry: ["src/index.ts"],
	format: ["esm"],
	target: "esnext",
	splitting: true,
	minify: true,
	dts: false,
	treeshake: true,
	clean: true,
	outDir: "dist",
	sourcemap: true,
	...options
}))
