export type EventMap = object

export interface BaseEvent<Type extends string, Payload> {
	readonly type: Type
	readonly payload: Payload
}

export type EventListener<Type extends string, Payload> = ((
	event: BaseEvent<Type, Payload>
) => Promise<void> | void) & { __once?: boolean; __priority?: PriorityLevel }

export const ListenerPriority = {
	LOW: 0,
	NORMAL: 1,
	HIGH: 2,
	CRITICAL: 3
} as const

export type PriorityLevel = (typeof ListenerPriority)[keyof typeof ListenerPriority]

export interface ListenerOptions {
	once?: boolean
	priority?: PriorityLevel
}

export interface TypedEventEmitter<TEventMap extends EventMap> {
	emit<K extends keyof TEventMap & string>(type: K, payload: TEventMap[K]): void

	on<K extends keyof TEventMap & string>(
		type: K,
		listener: EventListener<K, TEventMap[K]>,
		options?: ListenerOptions
	): () => void

	next<K extends keyof TEventMap & string>(type: K): Promise<TEventMap[K]>

	off<K extends keyof TEventMap & string>(
		type: K,
		listener: EventListener<K, TEventMap[K]>
	): void

	once<K extends keyof TEventMap & string>(
		type: K,
		listener: EventListener<K, TEventMap[K]>,
		priority?: PriorityLevel
	): () => void

	clear<K extends keyof TEventMap & string>(type?: K): void

	hasListeners<K extends keyof TEventMap & string>(type?: K): boolean

	listenerCount<K extends keyof TEventMap & string>(type?: K): number

	setMaxListeners<K extends keyof TEventMap & string>(limit: number, type?: K): void
}
