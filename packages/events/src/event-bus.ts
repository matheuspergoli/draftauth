import {
	type BaseEvent,
	type EventListener,
	type EventMap,
	type ListenerOptions,
	ListenerPriority,
	type PriorityLevel,
	type TypedEventEmitter
} from "./types"

export class Emitter<TEventMap extends EventMap> implements TypedEventEmitter<TEventMap> {
	readonly #listeners = new Map<
		keyof TEventMap,
		Map<EventListener<string, unknown>, PriorityLevel>
	>()
	readonly #maxListenersMap = new Map<keyof TEventMap, number>()
	readonly #eventBuffer = new Map<keyof TEventMap, { payload: unknown; timestamp: number }[]>()

	#MAX_BUFFER_AGE = 5000
	#warningThreshold = 10
	#defaultMaxListeners = -1

	constructor(options?: { defaultMaxListeners?: number; warningThreshold?: number }) {
		if (options?.defaultMaxListeners !== undefined) {
			this.#defaultMaxListeners = options.defaultMaxListeners
		}
		if (options?.warningThreshold !== undefined) {
			this.#warningThreshold = options.warningThreshold
		}
	}

	#removeListener<K extends keyof TEventMap & string>(
		type: K,
		listener: EventListener<string, unknown>
	): void {
		const eventListeners = this.#listeners.get(type)
		if (!eventListeners) return

		eventListeners.delete(listener)

		if (eventListeners.size === 0) {
			this.#listeners.delete(type)
		}
	}

	#executeListener<K extends keyof TEventMap & string>(
		listener: EventListener<K, TEventMap[K]>,
		event: BaseEvent<K, TEventMap[K]>,
		type: K,
		priority: PriorityLevel
	): void {
		try {
			const result = listener(event)

			if (result instanceof Promise) {
				Promise.resolve(result).catch((error) => {
					this.#handleListenerError(type, error, priority)
				})
			}
		} catch (error) {
			this.#handleListenerError(type, error, priority)
		}
	}

	#getMaxListeners<K extends keyof TEventMap & string>(type: K): number {
		return this.#maxListenersMap.get(type) ?? this.#defaultMaxListeners
	}

	#handleListenerError<K extends keyof TEventMap & string>(
		type: K,
		error: unknown,
		priority: PriorityLevel
	): void {
		console.error(`Event listener error (${type}, priority ${priority}):`, error)
	}

	#addToBuffer<K extends keyof TEventMap & string>(type: K, payload: unknown): void {
		const buffer = this.#eventBuffer.get(type) || []
		buffer.push({
			payload,
			timestamp: Date.now()
		})

		this.#eventBuffer.set(type, buffer)
	}

	#cleanBuffer(): void {
		const now = Date.now()

		for (const [type, events] of this.#eventBuffer) {
			const filtered = events.filter((event) => now - event.timestamp < this.#MAX_BUFFER_AGE)
			this.#eventBuffer.set(type, filtered)
		}
	}

	next<K extends keyof TEventMap & string>(type: K): Promise<TEventMap[K]> {
		this.#cleanBuffer()

		const buffered = this.#eventBuffer.get(type)
		if (buffered?.length) {
			return buffered.shift()?.payload as Promise<TEventMap[K]>
		}

		return new Promise((resolve) => {
			const disposableListener = (event: BaseEvent<K, TEventMap[K]>) => {
				this.off(type, disposableListener)
				resolve(event.payload)
			}
			this.on(type, disposableListener)
		})
	}

	emit<K extends keyof TEventMap & string>(type: K, payload: TEventMap[K]): void {
		this.#addToBuffer(type, payload)

		const eventListeners = this.#listeners.get(type)
		if (!eventListeners || eventListeners.size === 0) return

		const event = Object.freeze({ type, payload })

		const sortedListeners = Array.from(eventListeners.entries())
			.sort(([, a], [, b]) => b - a)
			.map(([listener]) => listener)

		for (const listener of sortedListeners) {
			const isOnce = listener.__once

			this.#executeListener(
				listener,
				event,
				type,
				eventListeners.get(listener) ?? ListenerPriority.NORMAL
			)

			if (isOnce) {
				this.#removeListener(type, listener)
			}
		}
	}

	on<K extends keyof TEventMap & string>(
		type: K,
		listener: EventListener<K, TEventMap[K]>,
		options?: ListenerOptions
	): () => void {
		if (typeof listener !== "function") {
			throw new TypeError("Event listener must be a function")
		}

		let listenerMap = this.#listeners.get(type)
		if (!listenerMap) {
			listenerMap = new Map()
			this.#listeners.set(type, listenerMap)
		}

		const priority = options?.priority ?? ListenerPriority.NORMAL

		if (options?.once) {
			listener.__once = true
		}

		listenerMap.set(listener as EventListener<string, unknown>, priority)

		const maxListeners = this.#getMaxListeners(type)
		if (maxListeners > 0 && listenerMap.size > maxListeners * this.#warningThreshold) {
			console.warn(
				`Potential memory leak: Listeners for '${String(type)}' exceed ${maxListeners}`
			)
		}

		return () => this.off(type, listener)
	}

	off<K extends keyof TEventMap & string>(
		type: K,
		listener: EventListener<K, TEventMap[K]>
	): void {
		this.#listeners.get(type)?.delete(listener as EventListener<string, unknown>)
		if (this.#listeners.get(type)?.size === 0) {
			this.#listeners.delete(type)
		}
	}

	once<K extends keyof TEventMap & string>(
		type: K,
		listener: EventListener<K, TEventMap[K]>,
		priority: PriorityLevel = ListenerPriority.NORMAL
	): () => void {
		return this.on(type, listener, { once: true, priority })
	}

	clear<K extends keyof TEventMap & string>(type?: K): void {
		if (type) {
			this.#listeners.delete(type)
		} else {
			this.#listeners.clear()
		}
	}

	hasListeners<K extends keyof TEventMap & string>(type?: K): boolean {
		if (type) {
			const listenerSet = this.#listeners.get(type)
			return !!listenerSet && listenerSet.size > 0
		}

		for (const listenerSet of this.#listeners.values()) {
			if (listenerSet.size > 0) {
				return true
			}
		}

		return false
	}

	listenerCount<K extends keyof TEventMap & string>(type?: K): number {
		if (type) {
			const listenerSet = this.#listeners.get(type)
			return listenerSet ? listenerSet.size : 0
		}

		let total = 0
		for (const [, listenerSet] of this.#listeners) {
			total += listenerSet.size
		}

		return total
	}

	setMaxListeners<K extends keyof TEventMap & string>(limit: number, type?: K): void {
		if (limit < -1) {
			throw new RangeError("The limit of event listeners must be >= -1")
		}

		if (type) {
			this.#maxListenersMap.set(type, limit)
		} else {
			this.#defaultMaxListeners = limit
		}
	}
}
