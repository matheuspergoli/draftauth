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

type Users = InferResponseType<typeof api.manage.users.$get>

export const usersTableColumns: ColumnDef<Users[number]>[] = [
	{
		accessorKey: "email",
		header: "Email"
	},
	{
		accessorKey: "userId",
		header: "User ID"
	},
	{
		accessorKey: "status",
		header: "Status",
		cell: ({ row }) => {
			const status = row.original.status

			switch (status) {
				case "active":
					return <Badge>Ativo</Badge>
				case "inactive":
					return <Badge variant="destructive">Inativo</Badge>
			}
		}
	},
	{
		id: "manage",
		cell: ({ row }) => {
			return (
				<Button asChild className="ml-auto block w-fit">
					<Link to="/dashboard/users/$id" params={{ id: row.original.userId }}>
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

export function UsersTable<TData, TValue>({ columns, data }: DataTableProps<TData, TValue>) {
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
			<div className="flex items-center py-4">
				<Input
					placeholder="Buscar usuário por email"
					value={(table.getColumn("email")?.getFilterValue() as string) ?? ""}
					onChange={(event) => table.getColumn("email")?.setFilterValue(event.target.value)}
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
