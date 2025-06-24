import { defineConfig, type Options } from "tsup"

export default defineConfig((options: Options) => ({
	entry: ["src/index.ts"],
	format: ["esm"],
	target: "esnext",
	splitting: true,
	minify: true,
	dts: true,
	treeshake: true,
	clean: true,
	outDir: "dist",
	sourcemap: true,
	...options
}))
