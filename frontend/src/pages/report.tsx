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
  const strings = task.strings
  const suspiciousStrings = strings?.suspicious || []
  const domains = strings?.domains || []
  const urls = strings?.urls || []
  const ips = strings?.ips || []

  return (
    <div className="space-y-6">
      {yaraMatches.length > 0 && (
        <div>
          <h3 className="mb-3 text-lg font-semibold">YARA 匹配 ({yaraMatches.length})</h3>
          <div className="space-y-3">
            {yaraMatches.map((match: any, idx: number) => (
              <div key={idx} className="rounded-lg border p-4">
                <div className="flex items-center gap-2 mb-2">
                  <Badge variant="destructive">{match.rule}</Badge>
                  {match.namespace && (
                    <Badge variant="outline">{match.namespace}</Badge>
                  )}
                  {match.tags?.map((tag: string, tidx: number) => (
                    <Badge key={tidx} variant="secondary">
                      {tag}
                    </Badge>
                  ))}
                </div>
                {match.meta && (
                  <div className="space-y-1 text-sm">
                    {match.meta.description && (
                      <p className="text-muted-foreground">{match.meta.description}</p>
                    )}
                    <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
                      {match.meta.author && <span>作者: {match.meta.author}</span>}
                      {match.meta.date && <span>日期: {match.meta.date}</span>}
                      {match.meta.score && <span>评分: {match.meta.score}</span>}
                      {match.meta.reference && (
                        <a href={match.meta.reference} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
                          参考链接
                        </a>
                      )}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {capaResults.length > 0 && (
        <div>
          <h3 className="mb-3 text-lg font-semibold">CAPA 能力检测 ({capaResults.length})</h3>
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

      {(domains.length > 0 || urls.length > 0 || ips.length > 0 || suspiciousStrings.length > 0) && (
        <div>
          <h3 className="mb-3 text-lg font-semibold">提取字符串</h3>
          <div className="grid gap-4 md:grid-cols-2">
            {domains.length > 0 && (
              <div className="rounded-lg border p-4">
                <h4 className="font-medium mb-2">域名 ({domains.length})</h4>
                <div className="space-y-1 font-mono text-sm">
                  {domains.map((d: string, idx: number) => (
                    <div key={idx} className="text-muted-foreground">{d}</div>
                  ))}
                </div>
              </div>
            )}
            {ips.length > 0 && (
              <div className="rounded-lg border p-4">
                <h4 className="font-medium mb-2">IP 地址 ({ips.length})</h4>
                <div className="space-y-1 font-mono text-sm">
                  {ips.map((ip: string, idx: number) => (
                    <div key={idx} className="text-muted-foreground">{ip}</div>
                  ))}
                </div>
              </div>
            )}
            {urls.length > 0 && (
              <div className="rounded-lg border p-4">
                <h4 className="font-medium mb-2">URL ({urls.length})</h4>
                <div className="space-y-1 font-mono text-sm">
                  {urls.slice(0, 20).map((url: string, idx: number) => (
                    <div key={idx} className="text-muted-foreground truncate">{url}</div>
                  ))}
                </div>
              </div>
            )}
            {suspiciousStrings.length > 0 && (
              <div className="rounded-lg border p-4">
                <h4 className="font-medium mb-2">可疑字符串 ({suspiciousStrings.length})</h4>
                <div className="space-y-1 font-mono text-sm">
                  {suspiciousStrings.slice(0, 20).map((s: string, idx: number) => (
                    <div key={idx} className="text-muted-foreground truncate">{s}</div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {capaResults.length === 0 && yaraMatches.length === 0 && !strings && (
        <div className="py-8 text-center text-muted-foreground">
          暂无静态分析数据
        </div>
      )}
    </div>
  )
}

function DynamicTab({ task }: { task: any }) {
  const da = task.dynamic_analysis || {}
  const processTree = da.process_tree || []
  const syscallSummary = da.syscall_summary || {}
  const networkSummary = da.network_summary || {}
  const fileActivity = da.file_activity || {}
  const eventTypes = da.event_types || []
  const skipped = da.skipped

  if (skipped) {
    return (
      <div className="py-8 text-center text-muted-foreground">
        动态分析已跳过
      </div>
    )
  }

  const hasData = processTree.length > 0 || Object.keys(syscallSummary).length > 0 || eventTypes.length > 0

  return (
    <div className="space-y-6">
      {da.success && (
        <div className="flex items-center gap-4 text-sm text-muted-foreground">
          <span>分析方法: <Badge variant="outline">{da.method}</Badge></span>
          <span>执行时间: {da.duration_seconds?.toFixed(2)}s</span>
          <span>事件数: {da.raw_events_count}</span>
        </div>
      )}

      {processTree.length > 0 && (
        <div>
          <h3 className="mb-3 text-lg font-semibold">进程树</h3>
          <div className="rounded-lg border p-4 font-mono text-sm">
            {processTree.map((proc: any, idx: number) => (
              <div key={idx}>
                <div className="flex items-center gap-2">
                  <Badge variant="outline">PID {proc.pid}</Badge>
                  <span className="font-medium">{proc.name}</span>
                </div>
                <div className="text-muted-foreground ml-4 truncate">{proc.cmdline}</div>
                {proc.children?.map((child: any, cidx: number) => (
                  <div key={cidx} className="ml-8 mt-2">
                    <div className="flex items-center gap-2">
                      <span className="text-muted-foreground">└─</span>
                      <Badge variant="outline">PID {child.pid}</Badge>
                      <span className="font-medium">{child.name}</span>
                    </div>
                    <div className="text-muted-foreground ml-8 truncate">{child.cmdline}</div>
                  </div>
                ))}
              </div>
            ))}
          </div>
        </div>
      )}

      {syscallSummary.by_type && Object.keys(syscallSummary.by_type).length > 0 && (
        <div>
          <h3 className="mb-3 text-lg font-semibold">系统调用统计 ({syscallSummary.total_count})</h3>
          <div className="flex flex-wrap gap-2">
            {Object.entries(syscallSummary.by_type).map(([name, count]: [string, any]) => (
              <Badge key={name} variant="secondary">
                {name}: {count}
              </Badge>
            ))}
          </div>
        </div>
      )}

      {eventTypes.length > 0 && (
        <div>
          <h3 className="mb-3 text-lg font-semibold">事件类型</h3>
          <div className="flex flex-wrap gap-2">
            {eventTypes.map((evt: string, idx: number) => (
              <Badge key={idx} variant="outline">{evt}</Badge>
            ))}
          </div>
        </div>
      )}

      {fileActivity && (fileActivity.created?.length > 0 || fileActivity.modified?.length > 0 || fileActivity.deleted?.length > 0) && (
        <div>
          <h3 className="mb-3 text-lg font-semibold">文件活动</h3>
          <div className="grid gap-4 md:grid-cols-3">
            {fileActivity.created?.length > 0 && (
              <div className="rounded-lg border p-3">
                <h4 className="font-medium mb-2 text-green-600">创建</h4>
                {fileActivity.created.map((f: string, idx: number) => (
                  <div key={idx} className="text-sm text-muted-foreground truncate">{f}</div>
                ))}
              </div>
            )}
            {fileActivity.modified?.length > 0 && (
              <div className="rounded-lg border p-3">
                <h4 className="font-medium mb-2 text-amber-600">修改</h4>
                {fileActivity.modified.map((f: string, idx: number) => (
                  <div key={idx} className="text-sm text-muted-foreground truncate">{f}</div>
                ))}
              </div>
            )}
            {fileActivity.deleted?.length > 0 && (
              <div className="rounded-lg border p-3">
                <h4 className="font-medium mb-2 text-red-600">删除</h4>
                {fileActivity.deleted.map((f: string, idx: number) => (
                  <div key={idx} className="text-sm text-muted-foreground truncate">{f}</div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {networkSummary && (networkSummary.total_dns_queries > 0 || networkSummary.total_connections > 0) && (
        <div>
          <h3 className="mb-3 text-lg font-semibold">网络活动</h3>
          <div className="flex gap-4">
            <div className="rounded-lg border p-3">
              <div className="text-2xl font-semibold">{networkSummary.total_dns_queries}</div>
              <div className="text-sm text-muted-foreground">DNS 查询</div>
            </div>
            <div className="rounded-lg border p-3">
              <div className="text-2xl font-semibold">{networkSummary.total_connections}</div>
              <div className="text-sm text-muted-foreground">网络连接</div>
            </div>
          </div>
        </div>
      )}

      {!hasData && (
        <div className="py-8 text-center text-muted-foreground">
          暂无动态分析数据
        </div>
      )}
    </div>
  )
}

function GhidraTab({ task }: { task: any }) {
  const ga = task.ghidra_analysis || {}
  const aiAnalysis = ga.ai_analysis || {}
  const analyzedFunctions = aiAnalysis.analyzed_functions || ga.analyzed_functions || []
  const keyFindings = aiAnalysis.key_findings || ga.key_findings || []
  const ghidraInfo = ga.ghidra_info || {}
  const analysisPath = aiAnalysis.analysis_path || []
  const malwareClass = aiAnalysis.malware_classification

  const hasData = analyzedFunctions.length > 0 || keyFindings.length > 0

  return (
    <div className="space-y-6">
      {ghidraInfo.file && (
        <div className="flex flex-wrap items-center gap-4 text-sm text-muted-foreground">
          <span>格式: <Badge variant="outline">{ghidraInfo.format}</Badge></span>
          <span>架构: {ghidraInfo.arch} {ghidraInfo.bits}位</span>
          <span>编译器: {ghidraInfo.compiler}</span>
          <span>大小: {ghidraInfo.human_size}</span>
        </div>
      )}

      {malwareClass && (
        <div className="rounded-lg border p-4 bg-red-50 dark:bg-red-950/20">
          <h3 className="text-lg font-semibold mb-2">恶意软件分类</h3>
          <div className="flex items-center gap-3">
            <Badge variant="destructive">{malwareClass.type}</Badge>
            {malwareClass.family && <span className="font-medium">家族: {malwareClass.family}</span>}
            <Badge variant={malwareClass.severity === 'CRITICAL' ? 'destructive' : 'secondary'}>
              {malwareClass.severity}
            </Badge>
          </div>
        </div>
      )}

      {keyFindings.length > 0 && (
        <div>
          <h3 className="mb-3 text-lg font-semibold">关键发现 ({keyFindings.length})</h3>
          <div className="space-y-3">
            {keyFindings.map((finding: any, idx: number) => (
              <div key={idx} className="rounded-lg border p-4">
                <div className="flex items-center gap-2 mb-2">
                  <Badge variant={
                    finding.severity === 'CRITICAL' ? 'destructive' 
                    : finding.severity === 'HIGH' ? 'destructive'
                    : finding.severity === 'MEDIUM' ? 'secondary' 
                    : 'outline'
                  }>
                    {finding.severity}
                  </Badge>
                  <span className="font-medium">{finding.title}</span>
                  {finding.category && (
                    <Badge variant="outline">{finding.category}</Badge>
                  )}
                </div>
                <p className="text-sm text-muted-foreground mb-2">{finding.description}</p>
                {finding.evidence && finding.evidence.length > 0 && (
                  <div className="mt-2">
                    <div className="text-xs font-medium text-muted-foreground mb-1">证据:</div>
                    <ul className="text-xs text-muted-foreground space-y-0.5 font-mono">
                      {finding.evidence.slice(0, 5).map((e: string, eidx: number) => (
                        <li key={eidx}>• {e}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {analyzedFunctions.length > 0 && (
        <div>
          <h3 className="mb-3 text-lg font-semibold">分析的函数 ({analyzedFunctions.length})</h3>
          <ScrollArea className="h-[400px] rounded-lg border">
            <div className="p-4 space-y-4">
              {analyzedFunctions.map((func: any, idx: number) => (
                <div key={idx} className="rounded-lg border p-4">
                  <div className="mb-2 flex items-center gap-2 flex-wrap">
                    <Code className="h-4 w-4 text-primary" />
                    <span className="font-mono font-medium">{func.name}</span>
                    <Badge variant="outline">{func.address}</Badge>
                    {func.risk && (
                      <Badge variant={
                        func.risk === 'critical' ? 'destructive'
                        : func.risk === 'high' ? 'destructive'
                        : func.risk === 'medium' ? 'secondary'
                        : 'outline'
                      }>
                        {func.risk}
                      </Badge>
                    )}
                  </div>
                  {func.purpose && (
                    <p className="text-sm font-medium mb-1">{func.purpose}</p>
                  )}
                  {func.analysis && (
                    <p className="text-sm text-muted-foreground">{func.analysis}</p>
                  )}
                </div>
              ))}
            </div>
          </ScrollArea>
        </div>
      )}

      {analysisPath.length > 0 && (
        <div>
          <h3 className="mb-3 text-lg font-semibold">分析路径</h3>
          <ol className="list-decimal list-inside space-y-1 text-sm text-muted-foreground">
            {analysisPath.map((step: string, idx: number) => (
              <li key={idx}>{step}</li>
            ))}
          </ol>
        </div>
      )}

      {!hasData && (
        <div className="py-8 text-center text-muted-foreground">
          暂无 Ghidra 分析数据
        </div>
      )}
    </div>
  )
}

function IOCTab({ task }: { task: any }) {
  const unifiedReport = task.unified_report || {}
  const mitreMapping = unifiedReport.mitre_mapping || []
  const iocs = unifiedReport.iocs || {}
  const sha256 = task.hashes?.sha256 || ''

  const domains = iocs.domains || []
  const ips = iocs.ips || []
  const urls = iocs.urls || []

  return (
    <div className="space-y-6">
      <div>
        <h3 className="mb-3 text-lg font-semibold">文件哈希</h3>
        <div className="rounded-lg border p-4">
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

      {(domains.length > 0 || ips.length > 0 || urls.length > 0) && (
        <div>
          <h3 className="mb-3 text-lg font-semibold">网络 IOC</h3>
          <div className="grid gap-4 md:grid-cols-2">
            {domains.length > 0 && (
              <div className="rounded-lg border p-4">
                <h4 className="font-medium mb-2">域名 ({domains.length})</h4>
                <div className="space-y-1">
                  {domains.map((d: any, idx: number) => (
                    <div key={idx} className="flex items-center gap-2">
                      <code className="font-mono text-sm">{d.value || d}</code>
                      {d.confidence && (
                        <Badge variant="outline" className="text-xs">{d.confidence}</Badge>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
            {ips.length > 0 && (
              <div className="rounded-lg border p-4">
                <h4 className="font-medium mb-2">IP 地址 ({ips.length})</h4>
                <div className="space-y-1">
                  {ips.map((ip: any, idx: number) => (
                    <div key={idx} className="font-mono text-sm">{ip.value || ip}</div>
                  ))}
                </div>
              </div>
            )}
            {urls.length > 0 && (
              <div className="rounded-lg border p-4 md:col-span-2">
                <h4 className="font-medium mb-2">URL ({urls.length})</h4>
                <div className="space-y-1">
                  {urls.slice(0, 10).map((url: any, idx: number) => (
                    <div key={idx} className="font-mono text-sm truncate">{url.value || url}</div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {mitreMapping.length > 0 && (
        <div>
          <h3 className="mb-3 text-lg font-semibold">MITRE ATT&CK 映射 ({mitreMapping.length})</h3>
          <div className="space-y-3">
            {mitreMapping.map((mapping: any, idx: number) => (
              <div key={idx} className="rounded-lg border p-4">
                <div className="flex items-center gap-2 mb-2 flex-wrap">
                  <Target className="h-4 w-4 text-primary" />
                  <Badge variant="destructive">{mapping.technique_id}</Badge>
                  <span className="font-medium">{mapping.technique_name}</span>
                  {mapping.tactic && (
                    <Badge variant="outline">{mapping.tactic}</Badge>
                  )}
                  {mapping.confidence && (
                    <Badge variant="secondary">{mapping.confidence}</Badge>
                  )}
                </div>
                {mapping.evidence && (
                  <p className="text-sm text-muted-foreground">{mapping.evidence}</p>
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
