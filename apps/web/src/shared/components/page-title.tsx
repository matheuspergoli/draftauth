import { cn } from "@/libs/utils"
import type React from "react"

export const PageTitle = ({ className, ...rest }: React.ComponentProps<"div">) => {
	return <div className={cn("font-bold text-2xl mb-5", className)} {...rest} />
}
