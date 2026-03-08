import { Link } from 'react-router-dom'
import {
  Clock,
  RefreshCw,
  Code,
  FileText,
  X,
  Plus,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { useTasks, useDeleteTask } from '@/hooks/use-tasks'
import type { TaskListItem } from '@/lib/api'

function formatTimeAgo(dateString: string) {
  const date = new Date(dateString)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffMins = Math.floor(diffMs / 60000)

  if (diffMins < 1) return '刚刚'
  if (diffMins < 60) return `${diffMins}分钟前`
  const diffHours = Math.floor(diffMins / 60)
  if (diffHours < 24) return `${diffHours}小时前`
  const diffDays = Math.floor(diffHours / 24)
  return `${diffDays}天前`
}



function TaskCard({ task }: { task: TaskListItem }) {
  const deleteTask = useDeleteTask()

  const isRunning = task.status === 'running'
  const isPending = task.status === 'pending'

  return (
    <div className="p-4 transition-colors hover:bg-muted/50">
      <div className="flex items-start gap-4">
        <div
          className={`relative flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-lg ${
            isRunning
              ? 'bg-primary/10'
              : isPending
                ? 'bg-amber-500/10'
                : 'bg-muted'
          }`}
        >
          <FileText
            className={`h-5 w-5 ${
              isRunning
                ? 'text-primary'
                : isPending
                  ? 'text-amber-500'
                  : 'text-muted-foreground'
            }`}
          />
          {isRunning && (
            <span className="absolute -right-1 -top-1 h-3 w-3 animate-pulse rounded-full bg-primary" />
          )}
        </div>

        <div className="min-w-0 flex-1">
          <div className="mb-1 flex items-center gap-2">
            <h3 className="truncate font-medium">{task.file_name}</h3>
            <Badge
              variant={isRunning ? 'default' : isPending ? 'secondary' : 'outline'}
            >
              {isRunning ? '分析中' : isPending ? '等待中' : task.status}
            </Badge>
          </div>
          <p className="text-sm text-muted-foreground">
            ID: <span className="font-mono">{task.id.slice(0, 8)}...</span>
            {task.file_type && ` · ${task.file_type}`}
          </p>

          {isRunning && (
            <div className="mt-3">
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <RefreshCw className="h-4 w-4 animate-spin text-primary" />
                分析进行中...
              </div>
            </div>
          )}

          {isPending && (
            <p className="mt-2 text-sm text-muted-foreground">
              等待分析...
            </p>
          )}
        </div>

        <div className="flex items-center gap-2">
          <span className="text-sm text-muted-foreground">
            {formatTimeAgo(task.created_at)}
          </span>
          <Button
            variant="ghost"
            size="icon"
            className="text-muted-foreground hover:text-destructive"
            onClick={() => deleteTask.mutate(task.id)}
            disabled={deleteTask.isPending}
          >
            <X className="h-5 w-5" />
          </Button>
        </div>
      </div>
    </div>
  )
}

export function TasksPage() {
  const { data: runningTasks } = useTasks({ status: 'running' })
  const { data: pendingTasks } = useTasks({ status: 'pending' })
  const { data: recentTasks } = useTasks({ limit: 10 })

  const activeTasks = [...(runningTasks || []), ...(pendingTasks || [])]
  const runningCount = runningTasks?.length ?? 0
  const pendingCount = pendingTasks?.length ?? 0
  
  // Show active tasks if any, otherwise show recent tasks
  const displayTasks = activeTasks.length > 0 ? activeTasks : (recentTasks || [])

  return (
    <div className="mx-auto max-w-6xl space-y-6 p-6">
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-amber-500/10">
                <Clock className="h-5 w-5 text-amber-500" />
              </div>
              <div>
                <p className="text-2xl font-semibold">{pendingCount}</p>
                <p className="text-sm text-muted-foreground">等待中</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                <RefreshCw className="h-5 w-5 animate-spin text-primary" />
              </div>
              <div>
                <p className="text-2xl font-semibold">{runningCount}</p>
                <p className="text-sm text-muted-foreground">分析中</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-purple-500/10">
                <Code className="h-5 w-5 text-purple-500" />
              </div>
              <div>
                <p className="text-2xl font-semibold">0</p>
                <p className="text-sm text-muted-foreground">Ghidra 队列</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-green-500/10">
                <FileText className="h-5 w-5 text-green-500" />
              </div>
              <div>
                <p className="text-2xl font-semibold">0</p>
                <p className="text-sm text-muted-foreground">报告队列</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="border-b">
          <CardTitle>
            {activeTasks.length > 0 ? '进行中的任务' : '最近的任务'}
          </CardTitle>
        </CardHeader>
        {displayTasks.length > 0 ? (
          <div className="divide-y">
            {displayTasks.map((task) => (
              <TaskCard key={task.id} task={task} />
            ))}
          </div>
        ) : (
          <CardContent className="py-12 text-center">
            <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-muted">
              <FileText className="h-8 w-8 text-muted-foreground" />
            </div>
            <h3 className="mb-2 text-lg font-medium">暂无任务</h3>
            <p className="mb-4 text-muted-foreground">上传文件开始新的分析</p>
            <Button asChild>
              <Link to="/">
                <Plus className="mr-2 h-5 w-5" />
                上传文件
              </Link>
            </Button>
          </CardContent>
        )}
      </Card>
    </div>
  )
}
