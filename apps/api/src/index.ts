import { auth } from "@/libs/auth"
import { Hono } from "hono"
import { contextStorage } from "hono/context-storage"
import { cors } from "hono/cors"
import { HTTPException } from "hono/http-exception"
import { poweredBy } from "hono/powered-by"
import { z } from "zod"
import { manageRouter } from "./routes/management"
import { serviceRouter } from "./routes/service"
import { setupRouter } from "./routes/setup"

const app = new Hono()

app.onError((error, c) => {
	console.log("=== Caught API Error ===")
	if (error instanceof HTTPException) {
		return c.text(error.message, error.status)
	}
	if (error instanceof z.ZodError) {
		return c.text(error.errors.map((err) => err.message).join(",\n"), 400)
	}
	console.error(error)
	return c.text("Something went wrong", 500)
})

app.use("/*", cors())
app.use(contextStorage())
app.use(poweredBy({ serverName: "Draft Auth" }))

const routes = app
	.basePath("/api")
	.route("/setup", setupRouter)
	.route("/manage", manageRouter)
	.route("/service", serviceRouter)

app.route("/", auth)

app.get("/", (c) => {
	return c.text("OK")
})

export default {
	fetch: app.fetch,
	port: process.env.PORT ?? 3000
}

export type ApiRoutes = typeof routes
