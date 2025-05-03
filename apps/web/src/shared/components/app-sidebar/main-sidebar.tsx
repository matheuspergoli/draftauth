import { Sidebar, SidebarContent, SidebarHeader, SidebarRail } from "../sidebar"
import { NavContent } from "./nav-content"
import { NavHeader } from "./nav-header"

export const MainSidebar = () => {
	return (
		<Sidebar collapsible="icon">
			<SidebarHeader>
				<NavHeader />
			</SidebarHeader>

			<SidebarContent>
				<NavContent />
			</SidebarContent>

			<SidebarRail />
		</Sidebar>
	)
}
