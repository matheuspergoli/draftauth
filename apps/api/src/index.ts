import { auth } from "@/libs/auth"
import { Hono } from "hono"
import { contextStorage } from "hono/context-storage"
import { cors } from "hono/cors"
import { HTTPException } from "hono/http-exception"
import { poweredBy } from "hono/powered-by"
import { z } from "zod"
import { env } from "./environment/env"
import { limitEmailRate, limitIpRate } from "./libs/rate-limit"
import { manageRouter } from "./routes/management"
import { serviceRouter } from "./routes/service"
import { setupRouter } from "./routes/setup"

const app = new Hono()

declare module "hono" {
	interface ContextVariableMap {
		currentAppId: string | undefined
		ipRateLimiter: typeof limitIpRate
		emailRateLimiter: typeof limitEmailRate
	}
}

app.onError((error, c) => {
	if (error instanceof HTTPException) {
		return c.text(error.message, error.status)
	}
	if (error instanceof z.ZodError) {
		return c.text(error.errors.map((err) => err.message).join(",\n"), 400)
	}
	return c.text("Something went wrong", 500)
})

app.use(
	"/*",
	cors({
		origin: env.FRONTEND_URL
	})
)
app.use("*", async (c, next) => {
	c.set("ipRateLimiter", limitIpRate)
	c.set("emailRateLimiter", limitEmailRate)
	await next()
})
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
