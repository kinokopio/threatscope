import { useParams, Link } from 'react-router-dom'
import {
  AlertTriangle,
  RefreshCw,
  Download,
  Share2,
  Copy,
  Check,
  FileText,
  Shield,
  Activity,
  Code,
  Target,
} from 'lucide-react'
import { useState } from 'react'
import { Card, CardContent, CardHeader } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Skeleton } from '@/components/ui/skeleton'
import { useTask, useReanalyzeTask, useExportTask } from '@/hooks/use-tasks'
import { toast } from 'sonner'

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    await navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <Button variant="ghost" size="icon" className="h-6 w-6" onClick={handleCopy}>
      {copied ? (
        <Check className="h-3 w-3 text-green-500" />
      ) : (
        <Copy className="h-3 w-3" />
      )}
    </Button>
  )
}

function VerdictIcon({ verdict }: { verdict?: string }) {
  const bgColor =
    verdict === 'malicious'
      ? 'bg-red-100 dark:bg-red-900/30'
      : verdict === 'suspicious'
        ? 'bg-amber-100 dark:bg-amber-900/30'
        : 'bg-green-100 dark:bg-green-900/30'

  const iconColor =
    verdict === 'malicious'
      ? 'text-red-500'
      : verdict === 'suspicious'
        ? 'text-amber-500'
        : 'text-green-500'

  return (
    <div
      className={`flex h-16 w-16 flex-shrink-0 items-center justify-center rounded-xl ${bgColor}`}
    >
      <AlertTriangle className={`h-8 w-8 ${iconColor}`} />
    </div>
  )
}



function OverviewTab({ task }: { task: any }) {
  const unifiedReport = task.unified_report || {}

  return (
    <div className="space-y-6">
      <div>
        <h3 className="mb-3 text-lg font-semibold">执行摘要</h3>
        <div className="rounded-lg bg-muted/50 p-4">
          <p className="leading-relaxed text-muted-foreground">
            {unifiedReport.summary ||
              '该样本正在分析中，完成后将显示详细的分析摘要。'}
          </p>
        </div>
      </div>

      {unifiedReport.techniques && unifiedReport.techniques.length > 0 && (
        <div>
          <h3 className="mb-3 text-lg font-semibold">检测能力</h3>
          <div className="flex flex-wrap gap-2">
            {unifiedReport.techniques.map((tech: any, idx: number) => (
              <Badge
                key={idx}
                variant={
                  tech.severity === 'high'
                    ? 'destructive'
                    : tech.severity === 'medium'
                      ? 'secondary'
                      : 'outline'
                }
              >
                {tech.name || tech.id}
              </Badge>
            ))}
          </div>
        </div>
      )}

      <div>
        <h3 className="mb-3 text-lg font-semibold">技术详情</h3>
        <div className="grid gap-4 md:grid-cols-2">
          <div className="rounded-lg bg-muted/50 p-4">
            <div className="mb-1 text-sm text-muted-foreground">文件类型</div>
            <div className="font-medium">
              {task.file_type?.format || task.file_type?.category || '-'}
            </div>
          </div>
          <div className="rounded-lg bg-muted/50 p-4">
            <div className="mb-1 text-sm text-muted-foreground">平台</div>
            <div className="font-medium">{task.file_type?.platform || '-'}</div>
          </div>
          <div className="rounded-lg bg-muted/50 p-4">
            <div className="mb-1 text-sm text-muted-foreground">MD5</div>
            <div className="truncate font-mono text-sm">
              {task.hashes?.md5 || '-'}
            </div>
          </div>
          <div className="rounded-lg bg-muted/50 p-4">
            <div className="mb-1 text-sm text-muted-foreground">SHA1</div>
            <div className="truncate font-mono text-sm">
              {task.hashes?.sha1 || '-'}
            </div>
          </div>
        </div>
      </div>

      {unifiedReport.recommendations && unifiedReport.recommendations.length > 0 && (
        <div>
          <h3 className="mb-3 text-lg font-semibold">建议措施</h3>
          <ul className="space-y-3">
            {unifiedReport.recommendations.map((rec: any, idx: number) => (
              <li key={idx} className="rounded-lg border p-3">
                <div className="flex items-center gap-2 mb-1">
                  <Shield className="h-4 w-4 text-primary" />
                  <span className="font-medium">{typeof rec === 'string' ? rec : rec.action}</span>
                  {rec.priority && (
                    <Badge variant={rec.priority === 'immediate' ? 'destructive' : rec.priority === 'high' ? 'secondary' : 'outline'}>
                      {rec.priority === 'immediate' ? '紧急' : rec.priority === 'high' ? '高' : '中'}
                    </Badge>
                  )}
                </div>
                {rec.details && (
                  <p className="text-sm text-muted-foreground ml-6">{rec.details}</p>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

function StaticTab({ task }: { task: any }) {
  const capaResults = task.capa?.capabilities || []
  const yaraMatches = task.yara?.matches || []
  const strings = task.strings?.strings || []

  return (
    <div className="space-y-6">
      {capaResults.length > 0 && (
        <div>
          <h3 className="mb-3 text-lg font-semibold">CAPA 能力检测</h3>
          <div className="space-y-2">
            {capaResults.map((cap: any, idx: number) => (
              <div key={idx} className="rounded-lg border p-3">
                <div className="font-medium">{cap.name}</div>
                <div className="text-sm text-muted-foreground">
                  {cap.namespace}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {yaraMatches.length > 0 && (
        <div>
          <h3 className="mb-3 text-lg font-semibold">YARA 匹配</h3>
          <div className="space-y-2">
            {yaraMatches.map((match: any, idx: number) => (
              <div key={idx} className="rounded-lg border p-3">
                <div className="flex items-center gap-2">
                  <Badge variant="destructive">{match.rule}</Badge>
                  {match.tags?.map((tag: string, tidx: number) => (
                    <Badge key={tidx} variant="outline">
                      {tag}
                    </Badge>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {strings.length > 0 && (
        <div>
          <h3 className="mb-3 text-lg font-semibold">
            提取字符串 ({strings.length})
          </h3>
          <ScrollArea className="h-[300px] rounded-lg border">
            <div className="p-4 font-mono text-sm">
              {strings.slice(0, 100).map((str: string, idx: number) => (
                <div key={idx} className="truncate py-0.5 text-muted-foreground">
                  {str}
                </div>
              ))}
            </div>
          </ScrollArea>
        </div>
      )}

      {capaResults.length === 0 && yaraMatches.length === 0 && strings.length === 0 && (
        <div className="py-8 text-center text-muted-foreground">
          暂无静态分析数据
        </div>
      )}
    </div>
  )
}

function DynamicTab({ task }: { task: any }) {
  const dynamicAnalysis = task.dynamic_analysis || {}
  const syscalls = dynamicAnalysis.syscalls || []
  const network = dynamicAnalysis.network || []
  const fileOps = dynamicAnalysis.file_operations || []

  return (
    <div className="space-y-6">
      {syscalls.length > 0 && (
        <div>
          <h3 className="mb-3 text-lg font-semibold">系统调用</h3>
          <ScrollArea className="h-[300px] rounded-lg border">
            <div className="p-4">
              {syscalls.map((call: any, idx: number) => (
                <div
                  key={idx}
                  className="flex items-center gap-4 border-b py-2 last:border-0"
                >
                  <Badge variant="outline">{call.name}</Badge>
                  <span className="truncate font-mono text-sm text-muted-foreground">
                    {call.args?.join(', ')}
                  </span>
                </div>
              ))}
            </div>
          </ScrollArea>
        </div>
      )}

      {network.length > 0 && (
        <div>
          <h3 className="mb-3 text-lg font-semibold">网络活动</h3>
          <div className="space-y-2">
            {network.map((net: any, idx: number) => (
              <div key={idx} className="rounded-lg border p-3">
                <div className="flex items-center gap-2">
                  <Badge>{net.type}</Badge>
                  <span className="font-mono">{net.destination}</span>
                  {net.port && (
                    <span className="text-muted-foreground">:{net.port}</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {fileOps.length > 0 && (
        <div>
          <h3 className="mb-3 text-lg font-semibold">文件操作</h3>
          <div className="space-y-2">
            {fileOps.map((op: any, idx: number) => (
              <div key={idx} className="rounded-lg border p-3">
                <Badge variant="secondary">{op.operation}</Badge>
                <span className="ml-2 font-mono text-sm">{op.path}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {syscalls.length === 0 && network.length === 0 && fileOps.length === 0 && (
        <div className="py-8 text-center text-muted-foreground">
          暂无动态分析数据
        </div>
      )}
    </div>
  )
}

function GhidraTab({ task }: { task: any }) {
  const ghidraAnalysis = task.ghidra_analysis || {}
  const functions = ghidraAnalysis.functions || []
  const imports = ghidraAnalysis.imports || []

  return (
    <div className="space-y-6">
      {functions.length > 0 && (
        <div>
          <h3 className="mb-3 text-lg font-semibold">
            函数列表 ({functions.length})
          </h3>
          <ScrollArea className="h-[400px] rounded-lg border">
            <div className="p-4 space-y-4">
              {functions.map((func: any, idx: number) => (
                <div key={idx} className="rounded-lg border p-4">
                  <div className="mb-2 flex items-center gap-2">
                    <Code className="h-4 w-4 text-primary" />
                    <span className="font-mono font-medium">{func.name}</span>
                    <Badge variant="outline">{func.address}</Badge>
                    <span className="text-sm text-muted-foreground">
                      {func.size} bytes
                    </span>
                  </div>
                  {func.decompiled && (
                    <pre className="mt-2 overflow-x-auto rounded bg-muted p-3 font-mono text-xs">
                      {func.decompiled}
                    </pre>
                  )}
                </div>
              ))}
            </div>
          </ScrollArea>
        </div>
      )}

      {imports.length > 0 && (
        <div>
          <h3 className="mb-3 text-lg font-semibold">导入函数</h3>
          <div className="flex flex-wrap gap-2">
            {imports.map((imp: string, idx: number) => (
              <Badge key={idx} variant="outline">
                {imp}
              </Badge>
            ))}
          </div>
        </div>
      )}

      {functions.length === 0 && imports.length === 0 && (
        <div className="py-8 text-center text-muted-foreground">
          暂无 Ghidra 分析数据
        </div>
      )}
    </div>
  )
}

function IOCTab({ task }: { task: any }) {
  const unifiedReport = task.unified_report || {}
  const techniques = unifiedReport.techniques || []
  const sha256 = task.hashes?.sha256 || ''

  return (
    <div className="space-y-6">
      <div>
        <h3 className="mb-3 text-lg font-semibold">IOC 指标</h3>
        <div className="space-y-4">
          <div className="rounded-lg border p-4">
            <div className="mb-2 text-sm font-medium text-muted-foreground">
              文件哈希
            </div>
            <div className="space-y-2">
              {task.hashes?.md5 && (
                <div className="flex items-center gap-2">
                  <Badge variant="outline">MD5</Badge>
                  <code className="flex-1 truncate font-mono text-sm">
                    {task.hashes.md5}
                  </code>
                  <CopyButton text={task.hashes.md5} />
                </div>
              )}
              {task.hashes?.sha1 && (
                <div className="flex items-center gap-2">
                  <Badge variant="outline">SHA1</Badge>
                  <code className="flex-1 truncate font-mono text-sm">
                    {task.hashes.sha1}
                  </code>
                  <CopyButton text={task.hashes.sha1} />
                </div>
              )}
              {sha256 && (
                <div className="flex items-center gap-2">
                  <Badge variant="outline">SHA256</Badge>
                  <code className="flex-1 truncate font-mono text-sm">
                    {sha256}
                  </code>
                  <CopyButton text={sha256} />
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {techniques.length > 0 && (
        <div>
          <h3 className="mb-3 text-lg font-semibold">MITRE ATT&CK 技术</h3>
          <div className="space-y-2">
            {techniques.map((tech: any, idx: number) => (
              <div key={idx} className="rounded-lg border p-4">
                <div className="flex items-center gap-2">
                  <Target className="h-4 w-4 text-primary" />
                  <Badge>{tech.id}</Badge>
                  <span className="font-medium">{tech.name}</span>
                </div>
                {tech.description && (
                  <p className="mt-2 text-sm text-muted-foreground">
                    {tech.description}
                  </p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

export function ReportPage() {
  const { id } = useParams<{ id: string }>()
  const { data: task, isLoading, error } = useTask(id || '')
  const reanalyze = useReanalyzeTask()
  const exportTask = useExportTask()

  const handleReanalyze = async () => {
    if (!id) return
    try {
      await reanalyze.mutateAsync({ id })
      toast.success('重新分析任务已创建')
    } catch {
      toast.error('重新分析失败')
    }
  }

  const handleExport = async () => {
    if (!id) return
    try {
      const blob = await exportTask.mutateAsync(id)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${task?.file_name || 'report'}_analysis.json`
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      toast.error('导出失败')
    }
  }

  if (isLoading) {
    return (
      <div className="mx-auto max-w-7xl space-y-6 p-6">
        <Card>
          <CardContent className="p-6">
            <div className="flex gap-6">
              <Skeleton className="h-16 w-16 rounded-xl" />
              <div className="flex-1 space-y-2">
                <Skeleton className="h-6 w-48" />
                <Skeleton className="h-4 w-96" />
                <Skeleton className="h-4 w-64" />
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    )
  }

  if (error || !task) {
    return (
      <div className="mx-auto max-w-7xl p-6">
        <Card>
          <CardContent className="py-12 text-center">
            <AlertTriangle className="mx-auto mb-4 h-12 w-12 text-muted-foreground" />
            <h2 className="mb-2 text-lg font-semibold">报告未找到</h2>
            <p className="mb-4 text-muted-foreground">
              请检查任务 ID 是否正确
            </p>
            <Button asChild>
              <Link to="/history">返回历史记录</Link>
            </Button>
          </CardContent>
        </Card>
      </div>
    )
  }

  const verdict = task.unified_report?.verdict
  const sha256 = task.hashes?.sha256 || ''
  const fileType = task.file_type?.format || task.file_type?.category || '-'

  return (
    <div className="mx-auto max-w-7xl space-y-6 p-6">
      <Card>
        <CardContent className="p-6">
          <div className="flex flex-col gap-6 lg:flex-row lg:items-start">
            <VerdictIcon verdict={verdict} />
            <div className="min-w-0 flex-1">
              <div className="mb-2 flex flex-wrap items-center gap-2">
                <h1 className="text-xl font-semibold">{task.file_name}</h1>
                <Badge
                  variant={
                    verdict === 'malicious'
                      ? 'destructive'
                      : verdict === 'suspicious'
                        ? 'secondary'
                        : 'outline'
                  }
                >
                  {verdict === 'malicious'
                    ? '恶意'
                    : verdict === 'suspicious'
                      ? '可疑'
                      : verdict === 'clean' || verdict === 'benign'
                        ? '安全'
                        : '未知'}
                </Badge>

              </div>
              <div className="mb-3 flex items-center gap-2">
                <span className="text-sm text-muted-foreground">SHA256:</span>
                <code className="rounded bg-muted px-2 py-0.5 font-mono text-sm">
                  {sha256 ? `${sha256.slice(0, 48)}...` : '-'}
                </code>
                {sha256 && <CopyButton text={sha256} />}
              </div>
              <div className="flex flex-wrap items-center gap-4 text-sm">
                <div className="flex items-center gap-2">
                  <span className="text-muted-foreground">文件类型:</span>
                  <span className="font-medium">{fileType}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-muted-foreground">状态:</span>
                  <Badge variant={task.status === 'completed' ? 'default' : task.status === 'failed' ? 'destructive' : 'secondary'}>
                    {task.status === 'completed' ? '已完成' 
                      : task.status === 'failed' ? '失败' 
                      : task.status === 'pending' ? '等待中'
                      : task.current_step || '分析中'}
                  </Badge>
                </div>
              </div>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button onClick={handleReanalyze} disabled={reanalyze.isPending}>
                <RefreshCw className="mr-2 h-4 w-4" />
                重新分析
              </Button>
              <Button
                variant="outline"
                onClick={handleExport}
                disabled={exportTask.isPending}
              >
                <Download className="mr-2 h-4 w-4" />
                导出 JSON
              </Button>
              <Button variant="outline">
                <Share2 className="mr-2 h-4 w-4" />
                分享
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <Tabs defaultValue="overview">
          <CardHeader className="border-b pb-0">
            <TabsList className="w-full justify-start rounded-none border-b-0 bg-transparent p-0">
              <TabsTrigger
                value="overview"
                className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent"
              >
                <FileText className="mr-2 h-4 w-4" />
                概要
              </TabsTrigger>
              <TabsTrigger
                value="static"
                className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent"
              >
                <Shield className="mr-2 h-4 w-4" />
                静态分析
              </TabsTrigger>
              <TabsTrigger
                value="dynamic"
                className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent"
              >
                <Activity className="mr-2 h-4 w-4" />
                动态分析
              </TabsTrigger>
              <TabsTrigger
                value="ghidra"
                className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent"
              >
                <Code className="mr-2 h-4 w-4" />
                Ghidra
              </TabsTrigger>
              <TabsTrigger
                value="ioc"
                className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent"
              >
                <Target className="mr-2 h-4 w-4" />
                IOC & MITRE
              </TabsTrigger>
            </TabsList>
          </CardHeader>
          <CardContent className="p-6">
            <TabsContent value="overview" className="m-0">
              <OverviewTab task={task} />
            </TabsContent>
            <TabsContent value="static" className="m-0">
              <StaticTab task={task} />
            </TabsContent>
            <TabsContent value="dynamic" className="m-0">
              <DynamicTab task={task} />
            </TabsContent>
            <TabsContent value="ghidra" className="m-0">
              <GhidraTab task={task} />
            </TabsContent>
            <TabsContent value="ioc" className="m-0">
              <IOCTab task={task} />
            </TabsContent>
          </CardContent>
        </Tabs>
      </Card>
    </div>
  )
}
