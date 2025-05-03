import { Link } from "@tanstack/react-router"

import { LayoutDashboard, List, Settings, User } from "lucide-react"
import {
	SidebarGroup,
	SidebarGroupLabel,
	SidebarMenu,
	SidebarMenuButton,
	SidebarMenuItem
} from "../sidebar"

export const NavContent = () => {
	return (
		<>
			<SidebarGroup>
				<SidebarGroupLabel>Menu Principal</SidebarGroupLabel>
				<SidebarMenu>
					<SidebarMenuItem>
						<SidebarMenuButton asChild tooltip="Início">
							<Link to="/dashboard">
								<LayoutDashboard />
								<span>Início</span>
							</Link>
						</SidebarMenuButton>
					</SidebarMenuItem>

					<SidebarMenuItem>
						<SidebarMenuButton asChild tooltip="Usuários">
							<Link to="/dashboard/users">
								<User />
								<span>Usuários</span>
							</Link>
						</SidebarMenuButton>
					</SidebarMenuItem>

					<SidebarMenuItem>
						<SidebarMenuButton asChild tooltip="Aplicações">
							<Link to="/dashboard/applications">
								<List />
								<span>Aplicações</span>
							</Link>
						</SidebarMenuButton>
					</SidebarMenuItem>

					<SidebarMenuItem>
						<SidebarMenuButton asChild tooltip="Configurações">
							<Link to="/dashboard/settings">
								<Settings />
								<span>Configurações</span>
							</Link>
						</SidebarMenuButton>
					</SidebarMenuItem>
				</SidebarMenu>
			</SidebarGroup>
		</>
	)
}
