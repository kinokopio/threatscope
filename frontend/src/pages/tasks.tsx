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
  Copy,
  Check,
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

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    await navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <Button variant="ghost" size="icon" className="h-6 w-6" onClick={handleCopy}>
      {copied ? <Check className="h-3 w-3 text-green-500" /> : <Copy className="h-3 w-3" />}
    </Button>
  )
}

function StepStatusIcon({ status }: { status: string }) {
  switch (status) {
    case 'completed':
      return <CheckCircle className="h-4 w-4 text-green-500 flex-shrink-0" />
    case 'running':
      return <RefreshCw className="h-4 w-4 animate-spin text-primary flex-shrink-0" />
    case 'failed':
      return <XCircle className="h-4 w-4 text-destructive flex-shrink-0" />
    default:
      return <Clock className="h-4 w-4 text-muted-foreground flex-shrink-0" />
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
        <div className="min-w-0 flex-1">
          <h3 className="font-semibold break-all">{task.file_name}</h3>
          <p className="text-sm text-muted-foreground font-mono break-all">{task.task_id}</p>
        </div>
        <Button variant="ghost" size="icon" onClick={onClose} className="flex-shrink-0 ml-2">
          <X className="h-5 w-5" />
        </Button>
      </div>

      <div className="p-4 border-b">
        <div className="flex items-center justify-between mb-2">
          <span className="text-sm font-medium">分析进度</span>
          <span className="text-sm text-muted-foreground">{completedSteps}/{totalSteps} ({progressPercent}%)</span>
        </div>
        <Progress value={progressPercent} className="h-2" />
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <Badge variant={isCompleted ? 'default' : isFailed ? 'destructive' : 'secondary'}>
            {isCompleted ? '已完成' : isFailed ? '失败' : task.current_step || '分析中'}
          </Badge>
          {task.file_type?.format && (
            <Badge variant="outline">{task.file_type.format}</Badge>
          )}
          {task.file_type?.platform && (
            <Badge variant="outline">{task.file_type.platform}</Badge>
          )}
          {task.file_type?.arch && (
            <Badge variant="outline">{task.file_type.arch}</Badge>
          )}
        </div>
      </div>

      <ScrollArea className="flex-1">
        <div className="p-4 space-y-6">
          <div>
            <h4 className="text-sm font-medium mb-3">分析步骤</h4>
            <div className="space-y-3">
              {steps.map(([stepId, stepData]) => {
                const step = stepData as { status: string; updated_at?: string; preview?: any }
                return (
                  <div key={stepId} className="flex items-start gap-3 p-2 rounded-lg bg-muted/30">
                    <StepStatusIcon status={step.status} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-sm font-medium">
                          {STEP_LABELS[stepId] || stepId}
                        </span>
                        <span className="text-xs text-muted-foreground flex-shrink-0">
                          {step.status === 'completed' ? '完成' : step.status === 'running' ? '运行中' : step.status === 'failed' ? '失败' : '等待'}
                        </span>
                      </div>
                      {step.preview && (
                        <div className="text-xs text-muted-foreground mt-1 space-y-0.5">
                          {typeof step.preview === 'object' 
                            ? Object.entries(step.preview).map(([k, v]) => (
                                <div key={k} className="break-all">
                                  <span className="font-medium">{k}:</span> {String(v)}
                                </div>
                              ))
                            : <div className="break-all">{String(step.preview)}</div>
                          }
                        </div>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
          </div>

          {task.hashes && (
            <div className="pt-4 border-t">
              <h4 className="text-sm font-medium mb-3">文件哈希</h4>
              <div className="space-y-2 text-xs font-mono bg-muted/30 p-3 rounded-lg">
                <div className="flex items-center gap-2">
                  <span className="text-muted-foreground w-16">MD5:</span>
                  <span className="break-all flex-1">{task.hashes.md5}</span>
                  <CopyButton text={task.hashes.md5} />
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-muted-foreground w-16">SHA1:</span>
                  <span className="break-all flex-1">{task.hashes.sha1}</span>
                  <CopyButton text={task.hashes.sha1} />
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-muted-foreground w-16">SHA256:</span>
                  <span className="break-all flex-1">{task.hashes.sha256}</span>
                  <CopyButton text={task.hashes.sha256} />
                </div>
                {task.hashes.ssdeep && (
                  <div className="flex items-center gap-2">
                    <span className="text-muted-foreground w-16">SSDEEP:</span>
                    <span className="break-all flex-1">{task.hashes.ssdeep}</span>
                    <CopyButton text={task.hashes.ssdeep} />
                  </div>
                )}
              </div>
            </div>
          )}

          {task.file_type && (
            <div className="pt-4 border-t">
              <h4 className="text-sm font-medium mb-3">文件类型</h4>
              <div className="grid grid-cols-2 gap-2 text-sm bg-muted/30 p-3 rounded-lg">
                <div>
                  <span className="text-muted-foreground">格式:</span>
                  <span className="ml-2">{task.file_type.format || '-'}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">架构:</span>
                  <span className="ml-2">{task.file_type.arch || '-'}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">类别:</span>
                  <span className="ml-2">{task.file_type.category || '-'}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">平台:</span>
                  <span className="ml-2">{task.file_type.platform || '-'}</span>
                </div>
              </div>
            </div>
          )}

          {task.yara?.matches && task.yara.matches.length > 0 && (
            <div className="pt-4 border-t">
              <h4 className="text-sm font-medium mb-3">YARA 匹配 ({task.yara.matches.length})</h4>
              <div className="space-y-2">
                {task.yara.matches.map((match: any, i: number) => (
                  <div key={i} className="p-3 rounded-lg bg-destructive/10 border border-destructive/20">
                    <div className="flex items-center gap-2 mb-2">
                      <Badge variant="destructive">{match.rule}</Badge>
                      {match.namespace && (
                        <span className="text-xs text-muted-foreground">{match.namespace}</span>
                      )}
                    </div>
                    {match.meta && Object.keys(match.meta).length > 0 && (
                      <div className="text-xs space-y-1">
                        {Object.entries(match.meta).map(([k, v]) => (
                          <div key={k} className="break-all">
                            <span className="text-muted-foreground">{k}:</span> {String(v)}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {task.strings && (
            <div className="pt-4 border-t">
              <h4 className="text-sm font-medium mb-3">提取的字符串</h4>
              <div className="space-y-3">
                {task.strings.urls && task.strings.urls.length > 0 && (
                  <div>
                    <span className="text-xs font-medium text-muted-foreground">URLs ({task.strings.urls.length})</span>
                    <div className="mt-1 p-2 bg-muted/30 rounded text-xs font-mono space-y-1">
                      {task.strings.urls.map((url: string, i: number) => (
                        <div key={i} className="break-all">{url}</div>
                      ))}
                    </div>
                  </div>
                )}
                {task.strings.domains && task.strings.domains.length > 0 && (
                  <div>
                    <span className="text-xs font-medium text-muted-foreground">Domains ({task.strings.domains.length})</span>
                    <div className="mt-1 p-2 bg-muted/30 rounded text-xs font-mono space-y-1">
                      {task.strings.domains.map((domain: string, i: number) => (
                        <div key={i} className="break-all">{domain}</div>
                      ))}
                    </div>
                  </div>
                )}
                {task.strings.ips && task.strings.ips.length > 0 && (
                  <div>
                    <span className="text-xs font-medium text-muted-foreground">IPs ({task.strings.ips.length})</span>
                    <div className="mt-1 p-2 bg-muted/30 rounded text-xs font-mono space-y-1">
                      {task.strings.ips.map((ip: string, i: number) => (
                        <div key={i} className="break-all">{ip}</div>
                      ))}
                    </div>
                  </div>
                )}
                {task.strings.suspicious && task.strings.suspicious.length > 0 && (
                  <div>
                    <span className="text-xs font-medium text-muted-foreground">可疑字符串 ({task.strings.suspicious.length})</span>
                    <div className="mt-1 p-2 bg-amber-500/10 rounded text-xs font-mono space-y-1">
                      {task.strings.suspicious.map((s: string, i: number) => (
                        <div key={i} className="break-all">{s}</div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {task.dynamic_analysis && (
            <div className="pt-4 border-t">
              <h4 className="text-sm font-medium mb-3">动态分析</h4>
              <div className="space-y-3">
                <div className="grid grid-cols-2 gap-2 text-sm bg-muted/30 p-3 rounded-lg">
                  <div>
                    <span className="text-muted-foreground">方法:</span>
                    <span className="ml-2">{task.dynamic_analysis.method || '-'}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">事件数:</span>
                    <span className="ml-2">{task.dynamic_analysis.raw_events_count || 0}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">耗时:</span>
                    <span className="ml-2">{task.dynamic_analysis.duration_seconds?.toFixed(2) || '-'}s</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">状态:</span>
                    <span className="ml-2">{task.dynamic_analysis.success ? '成功' : '失败'}</span>
                  </div>
                </div>

                {task.dynamic_analysis.syscall_summary?.by_type && (
                  <div>
                    <span className="text-xs font-medium text-muted-foreground">系统调用统计</span>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {Object.entries(task.dynamic_analysis.syscall_summary.by_type).map(([name, count]) => (
                        <Badge key={name} variant="outline" className="text-xs">
                          {name}: {String(count)}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {task.dynamic_analysis.network_summary && (
                  <div>
                    <span className="text-xs font-medium text-muted-foreground">网络活动</span>
                    <div className="mt-1 grid grid-cols-3 gap-2 text-xs bg-muted/30 p-2 rounded">
                      <div>DNS: {task.dynamic_analysis.network_summary.total_dns_queries || 0}</div>
                      <div>连接: {task.dynamic_analysis.network_summary.total_connections || 0}</div>
                      <div>HTTP: {task.dynamic_analysis.network_summary.http_requests?.length || 0}</div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {task.error && (
            <div className="pt-4 border-t">
              <h4 className="text-sm font-medium text-destructive mb-2">错误信息</h4>
              <div className="p-3 bg-destructive/10 rounded-lg text-sm text-destructive break-all">
                {task.error}
              </div>
            </div>
          )}
        </div>
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
            <h3 className="font-medium break-all">{task.file_name}</h3>
          </div>
          <div className="flex flex-wrap items-center gap-2">
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
            {task.file_type && (
              <Badge variant="outline">{task.file_type}</Badge>
            )}
            <span className="text-xs text-muted-foreground font-mono">{task.id}</span>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-shrink-0">
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
        <Card className="lg:col-span-2">
          <CardHeader className="border-b">
            <CardTitle>任务列表 ({displayTasks.length})</CardTitle>
          </CardHeader>
          {displayTasks.length > 0 ? (
            <ScrollArea className="h-[700px]">
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

        <Card className="lg:col-span-3">
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
