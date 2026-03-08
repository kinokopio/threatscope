import { useState, useMemo } from 'react'
import { Link } from 'react-router-dom'
import { type ColumnDef } from '@tanstack/react-table'
import { Search, Eye, Download, RotateCcw, Trash2, MoreHorizontal } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { DataTable } from '@/components/ui/data-table'
import { DataTableColumnHeader } from '@/components/ui/data-table-column-header'
import { DataTablePagination } from '@/components/ui/data-table-pagination'
import { useTasks, useDeleteTask, useExportTask } from '@/hooks/use-tasks'
import type { TaskListItem, TaskListParams } from '@/lib/api'

function formatDate(dateString: string) {
  const date = new Date(dateString)
  return date.toLocaleString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  })
}

function VerdictBadge({ verdict }: { verdict?: string }) {
  switch (verdict) {
    case 'malicious':
      return <Badge variant="destructive">恶意</Badge>
    case 'suspicious':
      return (
        <Badge className="bg-amber-500 hover:bg-amber-600 text-white">
          可疑
        </Badge>
      )
    case 'clean':
    case 'benign':
      return (
        <Badge className="bg-green-500 hover:bg-green-600 text-white">
          安全
        </Badge>
      )
    default:
      return <Badge variant="secondary">未知</Badge>
  }
}

function SeverityBadge({ verdict }: { verdict?: string }) {
  switch (verdict) {
    case 'malicious':
      return <Badge variant="destructive">高</Badge>
    case 'suspicious':
      return <Badge variant="secondary">中</Badge>
    case 'clean':
    case 'benign':
      return <Badge variant="outline">低</Badge>
    default:
      return <Badge variant="secondary">中</Badge>
  }
}

function StatusBadge({ status }: { status: string }) {
  switch (status) {
    case 'completed':
      return <Badge>已完成</Badge>
    case 'failed':
      return <Badge variant="destructive">失败</Badge>
    case 'pending':
      return <Badge variant="outline">等待中</Badge>
    default:
      return <Badge variant="secondary">分析中</Badge>
  }
}

function TaskActions({ task }: { task: TaskListItem }) {
  const deleteTask = useDeleteTask()
  const exportTask = useExportTask()

  const handleExport = async () => {
    const blob = await exportTask.mutateAsync(task.id)
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${task.file_name}_report.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" className="h-8 w-8 p-0">
          <span className="sr-only">打开菜单</span>
          <MoreHorizontal className="h-4 w-4" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem asChild>
          <Link to={`/report/${task.id}`}>
            <Eye className="mr-2 h-4 w-4" />
            查看报告
          </Link>
        </DropdownMenuItem>
        <DropdownMenuItem onClick={handleExport} disabled={exportTask.isPending}>
          <Download className="mr-2 h-4 w-4" />
          导出报告
        </DropdownMenuItem>
        <DropdownMenuItem>
          <RotateCcw className="mr-2 h-4 w-4" />
          重新分析
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem
          className="text-destructive"
          onClick={() => deleteTask.mutate(task.id)}
          disabled={deleteTask.isPending}
        >
          <Trash2 className="mr-2 h-4 w-4" />
          删除
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

export function HistoryPage() {
  const [filters, setFilters] = useState<TaskListParams>({
    status: 'completed',
    limit: 50,
  })
  const [search, setSearch] = useState('')

  const { data: tasks, isLoading } = useTasks({
    ...filters,
    search: search || undefined,
  })

  const columns = useMemo<ColumnDef<TaskListItem>[]>(() => [
    {
      accessorKey: 'file_name',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="文件名" />
      ),
      cell: ({ row }) => (
        <div>
          <p className="font-medium truncate max-w-[200px]">{row.original.file_name}</p>
          <p className="text-xs text-muted-foreground">
            {row.original.file_type || '-'}
          </p>
        </div>
      ),
    },
    {
      accessorKey: 'verdict',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="判定" />
      ),
      cell: ({ row }) => (
        <VerdictBadge verdict={row.original.result_summary?.verdict} />
      ),
      filterFn: (row, _id, value) => {
        const verdict = row.original.result_summary?.verdict
        return value.includes(verdict)
      },
    },
    {
      accessorKey: 'status',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="状态" />
      ),
      cell: ({ row }) => <StatusBadge status={row.original.status} />,
      filterFn: (row, id, value) => value.includes(row.getValue(id)),
    },
    {
      accessorKey: 'severity',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="严重程度" />
      ),
      cell: ({ row }) => (
        <SeverityBadge verdict={row.original.result_summary?.verdict} />
      ),
    },
    {
      accessorKey: 'summary',
      header: '摘要',
      cell: ({ row }) => (
        <span className="text-sm text-muted-foreground truncate max-w-[200px] block">
          {row.original.result_summary?.family || row.original.result_summary?.severity || '-'}
        </span>
      ),
    },
    {
      accessorKey: 'file_type',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="类型" />
      ),
      cell: ({ row }) => (
        <span className="text-sm">{row.original.file_type || '-'}</span>
      ),
    },
    {
      accessorKey: 'created_at',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="时间" />
      ),
      cell: ({ row }) => (
        <span className="text-sm text-muted-foreground">
          {formatDate(row.original.created_at)}
        </span>
      ),
    },
    {
      id: 'actions',
      cell: ({ row }) => <TaskActions task={row.original} />,
    },
  ], [])

  return (
    <div className="mx-auto max-w-7xl space-y-6 p-6">
      <Card>
        <CardContent className="p-4">
          <div className="flex flex-col gap-4 lg:flex-row">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="搜索文件名、哈希、家族..."
                className="pl-10"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>

            <Select
              value={filters.status || 'all'}
              onValueChange={(v) =>
                setFilters((f) => ({
                  ...f,
                  status: v === 'all' ? undefined : v,
                }))
              }
            >
              <SelectTrigger className="w-[140px]">
                <SelectValue placeholder="全部状态" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">全部状态</SelectItem>
                <SelectItem value="completed">已完成</SelectItem>
                <SelectItem value="failed">失败</SelectItem>
              </SelectContent>
            </Select>

            <Select
              value={filters.verdict || 'all'}
              onValueChange={(v) =>
                setFilters((f) => ({
                  ...f,
                  verdict: v === 'all' ? undefined : v,
                }))
              }
            >
              <SelectTrigger className="w-[140px]">
                <SelectValue placeholder="全部判定" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">全部判定</SelectItem>
                <SelectItem value="malicious">恶意</SelectItem>
                <SelectItem value="suspicious">可疑</SelectItem>
                <SelectItem value="clean">安全</SelectItem>
              </SelectContent>
            </Select>

            <Select
              value={filters.file_type || 'all'}
              onValueChange={(v) =>
                setFilters((f) => ({
                  ...f,
                  file_type: v === 'all' ? undefined : v,
                }))
              }
            >
              <SelectTrigger className="w-[160px]">
                <SelectValue placeholder="全部类型" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">全部类型</SelectItem>
                <SelectItem value="PE">PE (Windows)</SelectItem>
                <SelectItem value="ELF">ELF (Linux)</SelectItem>
                <SelectItem value="Mach-O">Mach-O (macOS)</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle>分析历史</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="py-12 text-center text-muted-foreground">
              加载中...
            </div>
          ) : tasks && tasks.length > 0 ? (
            <DataTable columns={columns} data={tasks} pageSize={10}>
              {(table) => (
                <DataTablePagination table={table} showRowSelection={false} />
              )}
            </DataTable>
          ) : (
            <div className="py-12 text-center text-muted-foreground">
              暂无分析记录
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
