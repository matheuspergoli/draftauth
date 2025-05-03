import type { api } from "@/libs/api"
import { Badge } from "@/shared/components/badge"
import { Button } from "@/shared/components/button"
import { Input } from "@/shared/components/input"
import {
	Table,
	TableBody,
	TableCell,
	TableHead,
	TableHeader,
	TableRow
} from "@/shared/components/table"
import { Link } from "@tanstack/react-router"
import {
	type ColumnDef,
	type ColumnFiltersState,
	flexRender,
	getCoreRowModel,
	getFilteredRowModel,
	useReactTable
} from "@tanstack/react-table"
import type { InferResponseType } from "hono/client"
import React from "react"
import { CreateApplicationDialog } from "./create-application-dialog"

type Applications = InferResponseType<typeof api.manage.applications.$get>

export const applicationTableColumns: ColumnDef<Applications[number]>[] = [
	{
		accessorKey: "appName",
		header: "Aplicação",
		cell: ({ row }) => {
			return row.original.appName
		}
	},
	{
		accessorKey: "appId",
		header: "App ID",
		cell: ({ row }) => {
			return <Badge>{row.original.appId}</Badge>
		}
	},
	{
		accessorKey: "rolesCount",
		header: "Cargos",
		cell: ({ row }) => {
			return <Badge>{row.original.rolesCount}</Badge>
		}
	},
	{
		accessorKey: "usersCount",
		header: "Usuários",
		cell: ({ row }) => {
			return <Badge>{row.original.usersCount}</Badge>
		}
	},
	{
		id: "manage",
		cell: ({ row }) => {
			return (
				<Button asChild className="block ml-auto w-fit">
					<Link to="/dashboard/applications/$appId" params={{ appId: row.original.appId }}>
						Gerenciar
					</Link>
				</Button>
			)
		}
	}
]

interface DataTableProps<TData, TValue> {
	columns: ColumnDef<TData, TValue>[]
	data: TData[]
}

export function ApplicationTable<TData, TValue>({
	columns,
	data
}: DataTableProps<TData, TValue>) {
	const [columnFilters, setColumnFilters] = React.useState<ColumnFiltersState>([])

	const table = useReactTable({
		data,
		columns,
		getCoreRowModel: getCoreRowModel(),
		onColumnFiltersChange: setColumnFilters,
		getFilteredRowModel: getFilteredRowModel(),
		state: {
			columnFilters
		}
	})

	return (
		<div>
			<div className="flex items-center py-4 gap-3">
				<CreateApplicationDialog />

				<Input
					placeholder="Buscar aplicação por nome"
					value={(table.getColumn("appName")?.getFilterValue() as string) ?? ""}
					onChange={(event) => table.getColumn("appName")?.setFilterValue(event.target.value)}
					className="max-w-sm"
				/>
			</div>

			<div className="rounded-md border">
				<Table>
					<TableHeader>
						{table.getHeaderGroups().map((headerGroup) => (
							<TableRow key={headerGroup.id}>
								{headerGroup.headers.map((header) => {
									return (
										<TableHead key={header.id}>
											{header.isPlaceholder
												? null
												: flexRender(header.column.columnDef.header, header.getContext())}
										</TableHead>
									)
								})}
							</TableRow>
						))}
					</TableHeader>
					<TableBody>
						{table.getRowModel().rows?.length ? (
							table.getRowModel().rows.map((row) => (
								<TableRow key={row.id} data-state={row.getIsSelected() && "selected"}>
									{row.getVisibleCells().map((cell) => (
										<TableCell key={cell.id}>
											{flexRender(cell.column.columnDef.cell, cell.getContext())}
										</TableCell>
									))}
								</TableRow>
							))
						) : (
							<TableRow>
								<TableCell colSpan={columns.length} className="h-24 text-center">
									Sem resultados.
								</TableCell>
							</TableRow>
						)}
					</TableBody>
				</Table>
			</div>
		</div>
	)
}
