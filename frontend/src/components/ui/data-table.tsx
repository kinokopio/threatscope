"use client"

import {
  type ColumnDef,
  type ColumnFiltersState,
  type SortingState,
  type VisibilityState,
  type Table as TanstackTable,
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
} from "@tanstack/react-table"
import * as React from "react"

import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { cn } from "@/lib/utils"

const DataTableContext = React.createContext<TanstackTable<unknown> | null>(null)

export function useDataTable<TData>() {
  const context = React.useContext(DataTableContext)
  if (!context) {
    throw new Error("useDataTable must be used within a DataTable")
  }
  return context as TanstackTable<TData>
}

interface DataTableProps<TData, TValue> {
  columns: ColumnDef<TData, TValue>[]
  data: TData[]
  children?: React.ReactNode | ((table: TanstackTable<TData>) => React.ReactNode)
  className?: string
  sorting?: SortingState
  onSortingChange?: React.Dispatch<React.SetStateAction<SortingState>>
  columnFilters?: ColumnFiltersState
  onColumnFiltersChange?: React.Dispatch<React.SetStateAction<ColumnFiltersState>>
  columnVisibility?: VisibilityState
  onColumnVisibilityChange?: React.Dispatch<React.SetStateAction<VisibilityState>>
  rowSelection?: Record<string, boolean>
  onRowSelectionChange?: React.Dispatch<React.SetStateAction<Record<string, boolean>>>
  pageSize?: number
  onRowClick?: (row: TData) => void
}

export function DataTable<TData, TValue>({
  columns,
  data,
  children,
  className,
  sorting: controlledSorting,
  onSortingChange,
  columnFilters: controlledFilters,
  onColumnFiltersChange,
  columnVisibility: controlledVisibility,
  onColumnVisibilityChange,
  rowSelection: controlledSelection,
  onRowSelectionChange,
  pageSize = 10,
  onRowClick,
}: DataTableProps<TData, TValue>) {
  const [internalSorting, setInternalSorting] = React.useState<SortingState>([])
  const [internalFilters, setInternalFilters] = React.useState<ColumnFiltersState>([])
  const [internalVisibility, setInternalVisibility] = React.useState<VisibilityState>({})
  const [internalSelection, setInternalSelection] = React.useState<Record<string, boolean>>({})

  const sorting = controlledSorting ?? internalSorting
  const setSorting = onSortingChange ?? setInternalSorting
  const columnFilters = controlledFilters ?? internalFilters
  const setColumnFilters = onColumnFiltersChange ?? setInternalFilters
  const columnVisibility = controlledVisibility ?? internalVisibility
  const setColumnVisibility = onColumnVisibilityChange ?? setInternalVisibility
  const rowSelection = controlledSelection ?? internalSelection
  const setRowSelection = onRowSelectionChange ?? setInternalSelection

  const table = useReactTable({
    data,
    columns,
    getCoreRowModel: getCoreRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    onSortingChange: setSorting,
    onColumnFiltersChange: setColumnFilters,
    onColumnVisibilityChange: setColumnVisibility,
    onRowSelectionChange: setRowSelection,
    state: {
      sorting,
      columnFilters,
      columnVisibility,
      rowSelection,
    },
    initialState: {
      pagination: {
        pageSize,
      },
    },
  })

  const childrenWithTable = typeof children === 'function' 
    ? children(table) 
    : children

  return (
    <DataTableContext.Provider value={table as TanstackTable<unknown>}>
      <div className={cn("space-y-4", className)}>
        {childrenWithTable}
        <div className="overflow-hidden rounded-md border">
          <Table>
            <TableHeader>
              {table.getHeaderGroups().map((headerGroup) => (
                <TableRow key={headerGroup.id}>
                  {headerGroup.headers.map((header) => (
                    <TableHead key={header.id}>
                      {header.isPlaceholder
                        ? null
                        : flexRender(
                            header.column.columnDef.header,
                            header.getContext()
                          )}
                    </TableHead>
                  ))}
                </TableRow>
              ))}
            </TableHeader>
            <TableBody>
              {table.getRowModel().rows?.length ? (
                table.getRowModel().rows.map((row) => (
                  <TableRow
                    key={row.id}
                    data-state={row.getIsSelected() ? "selected" : undefined}
                    className={onRowClick ? "cursor-pointer" : undefined}
                    onClick={onRowClick ? () => onRowClick(row.original as TData) : undefined}
                  >
                    {row.getVisibleCells().map((cell) => (
                      <TableCell key={cell.id}>
                        {flexRender(
                          cell.column.columnDef.cell,
                          cell.getContext()
                        )}
                      </TableCell>
                    ))}
                  </TableRow>
                ))
              ) : (
                <TableRow>
                  <TableCell
                    colSpan={columns.length}
                    className="h-24 text-center"
                  >
                    暂无数据
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
      </div>
    </DataTableContext.Provider>
  )
}

export type { ColumnDef, SortingState, ColumnFiltersState, VisibilityState }
