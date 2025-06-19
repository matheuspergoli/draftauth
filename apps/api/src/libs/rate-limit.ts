import { Ratelimit } from "@upstash/ratelimit"
import { Redis } from "@upstash/redis"
import { env } from "@/environment/env"

const redisClient = new Redis({
	url: env.REDIS_URL,
	token: env.REDIS_TOKEN
})

const ipEphemeralCache = new Map<string, number>()
let ipRateLimiterInstance: Ratelimit | undefined

const getIpRateLimiterInstance = () => {
	if (ipRateLimiterInstance === undefined) {
		ipRateLimiterInstance = new Ratelimit({
			redis: redisClient,
			ephemeralCache: ipEphemeralCache,
			limiter: Ratelimit.slidingWindow(3, "60 s"),
			prefix: "ratelimit_ip",
			analytics: true
		})
	}
	return ipRateLimiterInstance
}

export const limitIpRate = async (identifier: string) => {
	const limiter = getIpRateLimiterInstance()
	try {
		const result = await limiter.limit(identifier)
		return { success: result.success, remaining: result.remaining }
	} catch {
		return { success: false, remaining: 0 }
	}
}

const emailEphemeralCache = new Map<string, number>()
let emailRateLimiterInstance: Ratelimit | undefined

const getEmailRateLimiterInstance = () => {
	if (emailRateLimiterInstance === undefined) {
		emailRateLimiterInstance = new Ratelimit({
			redis: redisClient,
			ephemeralCache: emailEphemeralCache,
			limiter: Ratelimit.slidingWindow(3, "10 m"),
			prefix: "ratelimit_email"
		})
	}
	return emailRateLimiterInstance
}

export const limitEmailRate = async (identifier: string) => {
	const limiter = getEmailRateLimiterInstance()
	try {
		const result = await limiter.limit(identifier)
		return { success: result.success, remaining: result.remaining }
	} catch {
		return { success: false, remaining: 0 }
	}
}
