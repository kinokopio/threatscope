import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Clock,
  RefreshCw,
  Code,
  FileText,
  X,
  Plus,
  CheckCircle,
  XCircle,
  ChevronRight,
  Eye,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { ScrollArea } from '@/components/ui/scroll-area'
import { useTasks, useTask, useDeleteTask } from '@/hooks/use-tasks'
import type { TaskListItem } from '@/lib/api'

const RUNNING_STATUSES = ['static_analysis', 'dynamic_analysis', 'ghidra_analysis', 'report_generation', 'queued']

const STEP_LABELS: Record<string, string> = {
  hashing: '哈希计算',
  file_identification: '文件识别',
  capa: '能力分析 (CAPA)',
  strings: '字符串提取',
  yara: 'YARA 扫描',
  threat_intel: '威胁情报',
  dynamic: '动态分析',
  ghidra: 'Ghidra 分析',
  report: '报告生成',
}

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

function StepStatusIcon({ status }: { status: string }) {
  switch (status) {
    case 'completed':
      return <CheckCircle className="h-4 w-4 text-green-500" />
    case 'running':
      return <RefreshCw className="h-4 w-4 animate-spin text-primary" />
    case 'failed':
      return <XCircle className="h-4 w-4 text-destructive" />
    default:
      return <Clock className="h-4 w-4 text-muted-foreground" />
  }
}

function TaskDetailPanel({ taskId, onClose }: { taskId: string; onClose: () => void }) {
  const { data: task, isLoading } = useTask(taskId)

  if (isLoading) {
    return (
      <div className="p-6">
        <div className="flex items-center justify-center py-12">
          <RefreshCw className="h-8 w-8 animate-spin text-primary" />
        </div>
      </div>
    )
  }

  if (!task) {
    return (
      <div className="p-6 text-center text-muted-foreground">
        任务未找到
      </div>
    )
  }

  const stepsProgress = task.steps_progress || {}
  const steps = Object.entries(stepsProgress)
  const completedSteps = steps.filter(([, s]) => (s as any).status === 'completed').length
  const totalSteps = steps.length || 1
  const progressPercent = Math.round((completedSteps / totalSteps) * 100)

  const isCompleted = task.status === 'completed'
  const isFailed = task.status === 'failed'

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center justify-between border-b p-4">
        <div>
          <h3 className="font-semibold">{task.file_name}</h3>
          <p className="text-sm text-muted-foreground font-mono">{task.task_id?.slice(0, 8)}...</p>
        </div>
        <Button variant="ghost" size="icon" onClick={onClose}>
          <X className="h-5 w-5" />
        </Button>
      </div>

      <div className="p-4 border-b">
        <div className="flex items-center justify-between mb-2">
          <span className="text-sm font-medium">分析进度</span>
          <span className="text-sm text-muted-foreground">{progressPercent}%</span>
        </div>
        <Progress value={progressPercent} className="h-2" />
        <div className="mt-2 flex items-center gap-2">
          <Badge variant={isCompleted ? 'default' : isFailed ? 'destructive' : 'secondary'}>
            {isCompleted ? '已完成' : isFailed ? '失败' : task.current_step || '分析中'}
          </Badge>
          {task.file_type?.format && (
            <Badge variant="outline">{task.file_type.format}</Badge>
          )}
        </div>
      </div>

      <ScrollArea className="flex-1 p-4">
        <div className="space-y-3">
          {steps.map(([stepId, stepData]) => {
            const step = stepData as { status: string; updated_at?: string; preview?: any }
            return (
              <div key={stepId} className="flex items-start gap-3">
                <StepStatusIcon status={step.status} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium">
                      {STEP_LABELS[stepId] || stepId}
                    </span>
                    <span className="text-xs text-muted-foreground">
                      {step.status === 'completed' ? '完成' : step.status === 'running' ? '运行中' : step.status === 'failed' ? '失败' : '等待'}
                    </span>
                  </div>
                  {step.preview && (
                    <p className="text-xs text-muted-foreground mt-1 truncate">
                      {typeof step.preview === 'object' 
                        ? Object.entries(step.preview).slice(0, 2).map(([k, v]) => `${k}: ${v}`).join(', ')
                        : String(step.preview)
                      }
                    </p>
                  )}
                </div>
              </div>
            )
          })}
        </div>

        {task.hashes && (
          <div className="mt-6 pt-4 border-t">
            <h4 className="text-sm font-medium mb-2">文件哈希</h4>
            <div className="space-y-1 text-xs font-mono text-muted-foreground">
              <p>MD5: {task.hashes.md5}</p>
              <p>SHA256: {task.hashes.sha256?.slice(0, 32)}...</p>
            </div>
          </div>
        )}

        {task.yara?.matches && task.yara.matches.length > 0 && (
          <div className="mt-4 pt-4 border-t">
            <h4 className="text-sm font-medium mb-2">YARA 匹配</h4>
            <div className="flex flex-wrap gap-1">
              {task.yara.matches.map((match: any, i: number) => (
                <Badge key={i} variant="destructive" className="text-xs">
                  {match.rule}
                </Badge>
              ))}
            </div>
          </div>
        )}

        {task.error && (
          <div className="mt-4 pt-4 border-t">
            <h4 className="text-sm font-medium text-destructive mb-2">错误信息</h4>
            <p className="text-xs text-destructive">{task.error}</p>
          </div>
        )}
      </ScrollArea>

      <div className="border-t p-4">
        {isCompleted ? (
          <Button asChild className="w-full">
            <Link to={`/report/${task.task_id}`}>
              <Eye className="mr-2 h-4 w-4" />
              查看完整报告
            </Link>
          </Button>
        ) : (
          <p className="text-center text-sm text-muted-foreground">
            分析完成后可查看完整报告
          </p>
        )}
      </div>
    </div>
  )
}

function TaskCard({ task, isSelected, onSelect }: { task: TaskListItem; isSelected: boolean; onSelect: () => void }) {
  const deleteTask = useDeleteTask()

  const isRunning = RUNNING_STATUSES.includes(task.status)
  const isPending = task.status === 'pending'
  const isCompleted = task.status === 'completed'
  const isFailed = task.status === 'failed'

  return (
    <div 
      className={`p-4 transition-colors cursor-pointer ${isSelected ? 'bg-muted' : 'hover:bg-muted/50'}`}
      onClick={onSelect}
    >
      <div className="flex items-start gap-4">
        <div
          className={`relative flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-lg ${
            isRunning
              ? 'bg-primary/10'
              : isPending
                ? 'bg-amber-500/10'
                : isCompleted
                  ? 'bg-green-500/10'
                  : isFailed
                    ? 'bg-destructive/10'
                    : 'bg-muted'
          }`}
        >
          <FileText
            className={`h-5 w-5 ${
              isRunning
                ? 'text-primary'
                : isPending
                  ? 'text-amber-500'
                  : isCompleted
                    ? 'text-green-500'
                    : isFailed
                      ? 'text-destructive'
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
              variant={
                isCompleted ? 'default' 
                : isFailed ? 'destructive'
                : isRunning ? 'secondary' 
                : 'outline'
              }
            >
              {isCompleted ? '已完成' : isFailed ? '失败' : isRunning ? '分析中' : isPending ? '等待中' : task.status}
            </Badge>
          </div>
          <p className="text-sm text-muted-foreground">
            ID: <span className="font-mono">{task.id.slice(0, 8)}...</span>
            {task.file_type && ` · ${task.file_type}`}
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-sm text-muted-foreground">
            {formatTimeAgo(task.created_at)}
          </span>
          <Button
            variant="ghost"
            size="icon"
            className="text-muted-foreground hover:text-destructive"
            onClick={(e) => {
              e.stopPropagation()
              deleteTask.mutate(task.id)
            }}
            disabled={deleteTask.isPending}
          >
            <X className="h-5 w-5" />
          </Button>
          <ChevronRight className="h-5 w-5 text-muted-foreground" />
        </div>
      </div>
    </div>
  )
}

export function TasksPage() {
  const [selectedTaskId, setSelectedTaskId] = useState<string | null>(null)
  const { data: allTasks } = useTasks({ limit: 50 })

  const pendingTasks = allTasks?.filter(t => t.status === 'pending') || []
  const runningTasks = allTasks?.filter(t => RUNNING_STATUSES.includes(t.status)) || []
  const runningCount = runningTasks.length
  const pendingCount = pendingTasks.length
  
  const displayTasks = allTasks || []

  return (
    <div className="mx-auto max-w-7xl space-y-6 p-6">
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
                {runningCount > 0 ? (
                  <RefreshCw className="h-5 w-5 animate-spin text-primary" />
                ) : (
                  <RefreshCw className="h-5 w-5 text-primary" />
                )}
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
                <p className="text-2xl font-semibold">{allTasks?.filter(t => t.status === 'completed').length || 0}</p>
                <p className="text-sm text-muted-foreground">已完成</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-6 lg:grid-cols-5">
        <Card className="lg:col-span-3">
          <CardHeader className="border-b">
            <CardTitle>任务列表</CardTitle>
          </CardHeader>
          {displayTasks.length > 0 ? (
            <ScrollArea className="h-[600px]">
              <div className="divide-y">
                {displayTasks.map((task) => (
                  <TaskCard 
                    key={task.id} 
                    task={task} 
                    isSelected={selectedTaskId === task.id}
                    onSelect={() => setSelectedTaskId(task.id)}
                  />
                ))}
              </div>
            </ScrollArea>
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

        <Card className="lg:col-span-2">
          <CardHeader className="border-b">
            <CardTitle>任务详情</CardTitle>
          </CardHeader>
          {selectedTaskId ? (
            <TaskDetailPanel 
              taskId={selectedTaskId} 
              onClose={() => setSelectedTaskId(null)} 
            />
          ) : (
            <CardContent className="py-12 text-center">
              <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-muted">
                <Eye className="h-8 w-8 text-muted-foreground" />
              </div>
              <h3 className="mb-2 text-lg font-medium">选择任务</h3>
              <p className="text-muted-foreground">点击左侧任务查看详情</p>
            </CardContent>
          )}
        </Card>
      </div>
    </div>
  )
}
