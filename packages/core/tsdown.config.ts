import { type Options, defineConfig } from "tsdown"

export default defineConfig((options: Options) => ({
	entry: ["src/**.ts"],
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
