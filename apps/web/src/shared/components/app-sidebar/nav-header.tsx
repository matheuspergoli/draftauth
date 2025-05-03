import { Link } from "@tanstack/react-router"
import { SidebarMenu, SidebarMenuButton, SidebarMenuItem } from "../sidebar"

export const NavHeader = () => {
	return (
		<SidebarMenu>
			<SidebarMenuItem>
				<SidebarMenuButton asChild className="text-xl font-bold">
					<Link to="/dashboard">
						<span>Draft Auth Admin</span>
					</Link>
				</SidebarMenuButton>
			</SidebarMenuItem>
		</SidebarMenu>
	)
}
