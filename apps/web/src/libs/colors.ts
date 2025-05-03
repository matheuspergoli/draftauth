export const baseColors = [
	{
		name: "default",
		label: "Padrão"
	},
	{
		name: "cosmic-night",
		label: "Cosmic Night"
	},
	{
		name: "perpetuity",
		label: "Perpetuity"
	},
	{
		name: "caffeine",
		label: "Caffeine"
	},
	{
		name: "modern-minimal",
		label: "Modern Minimal"
	},
	{
		name: "retro-arcade",
		label: "Retro Arcade"
	},
	{
		name: "kodama-grove",
		label: "Kodama Grove"
	},
	{
		name: "claude",
		label: "Claude"
	},
	{
		name: "claymorphism",
		label: "Claymorphism"
	},
	{
		name: "vintage-paper",
		label: "Vintange Paper"
	}
] as const

export type BaseColor = (typeof baseColors)[number]
