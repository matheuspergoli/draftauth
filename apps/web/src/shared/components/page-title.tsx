import type React from "react"
import { cn } from "@/libs/utils"

export const PageTitle = ({ className, ...rest }: React.ComponentProps<"div">) => {
	return <div className={cn("font-bold text-2xl mb-5", className)} {...rest} />
}
