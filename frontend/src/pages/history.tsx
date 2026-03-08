import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Search, Eye, Download, RotateCcw, Trash2 } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
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
      return (
        <Badge className="bg-green-500 hover:bg-green-600 text-white">
          安全
        </Badge>
      )
    default:
      return <Badge variant="secondary">未知</Badge>
  }
}

function TaskRow({ task }: { task: TaskListItem }) {
  const deleteTask = useDeleteTask()
  const exportTask = useExportTask()
  const verdict = task.result_summary?.verdict

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
    <TableRow>
      <TableCell>
        <div>
          <p className="font-medium truncate max-w-[200px]">{task.file_name}</p>
          <p className="text-xs text-muted-foreground">
            {task.file_type || '-'}
          </p>
        </div>
      </TableCell>
      <TableCell>
        <VerdictBadge verdict={verdict} />
      </TableCell>
      <TableCell>
        <Badge
          variant={
            task.status === 'completed'
              ? 'default'
              : task.status === 'failed'
                ? 'destructive'
                : 'secondary'
          }
        >
          {task.status === 'completed'
            ? '已完成'
            : task.status === 'failed'
              ? '失败'
              : task.status === 'pending'
                ? '等待中'
                : '分析中'}
        </Badge>
      </TableCell>
      <TableCell>
        {verdict === 'malicious' ? (
          <Badge variant="destructive">高</Badge>
        ) : verdict === 'suspicious' ? (
          <Badge variant="secondary">中</Badge>
        ) : (
          <Badge variant="outline">低</Badge>
        )}
      </TableCell>
      <TableCell>
        <span className="text-sm text-muted-foreground truncate max-w-[200px] block">
          {task.result_summary || '-'}
        </span>
      </TableCell>
      <TableCell>
        <span className="text-sm">{task.file_type || '-'}</span>
      </TableCell>
      <TableCell>
        <span className="text-sm text-muted-foreground">
          {formatDate(task.created_at)}
        </span>
      </TableCell>
      <TableCell>
        <div className="flex items-center gap-1">
          <Button variant="ghost" size="icon" asChild>
            <Link to={`/report/${task.id}`}>
              <Eye className="h-4 w-4" />
            </Link>
          </Button>
          <Button
            variant="ghost"
            size="icon"
            onClick={handleExport}
            disabled={exportTask.isPending}
          >
            <Download className="h-4 w-4" />
          </Button>
          <Button variant="ghost" size="icon">
            <RotateCcw className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className="text-muted-foreground hover:text-destructive"
            onClick={() => deleteTask.mutate(task.id)}
            disabled={deleteTask.isPending}
          >
            <Trash2 className="h-4 w-4" />
          </Button>
        </div>
      </TableCell>
    </TableRow>
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
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>文件名</TableHead>
                <TableHead>判定</TableHead>
                <TableHead>状态</TableHead>
                <TableHead>严重程度</TableHead>
                <TableHead>摘要</TableHead>
                <TableHead>类型</TableHead>
                <TableHead>时间</TableHead>
                <TableHead>操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading ? (
                <TableRow>
                  <TableCell colSpan={8} className="text-center py-8">
                    加载中...
                  </TableCell>
                </TableRow>
              ) : tasks && tasks.length > 0 ? (
                tasks.map((task) => <TaskRow key={task.id} task={task} />)
              ) : (
                <TableRow>
                  <TableCell
                    colSpan={8}
                    className="text-center py-8 text-muted-foreground"
                  >
                    暂无分析记录
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
      </Card>
    </div>
  )
}
