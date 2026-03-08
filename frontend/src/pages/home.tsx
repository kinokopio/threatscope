import { useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Upload,
  Link as LinkIcon,
  Hash,
  ChevronRight,
  BarChart3,
  AlertTriangle,
  RefreshCw,
  Search,
  FileText,
  Cpu,
  Code,
  FileOutput,
  TrendingUp,
} from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible'
import { useStats } from '@/hooks/use-stats'
import { useCreateTask } from '@/hooks/use-tasks'
import { toast } from 'sonner'

export function HomePage() {
  const navigate = useNavigate()
  const { data: stats } = useStats()
  const createTask = useCreateTask()

  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [isDragging, setIsDragging] = useState(false)
  const [advancedOpen, setAdvancedOpen] = useState(false)
  const [options, setOptions] = useState({
    enable_capa: true,
    enable_strings: true,
    enable_yara: true,
    enable_dynamic: true,
    enable_ghidra: true,
  })

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(false)
    const files = e.dataTransfer.files
    if (files.length > 0) {
      setSelectedFile(files[0])
    }
  }, [])

  const handleFileSelect = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const files = e.target.files
      if (files && files.length > 0) {
        setSelectedFile(files[0])
      }
    },
    []
  )

  const handleSubmit = async () => {
    if (!selectedFile) {
      toast.error('请选择要分析的文件')
      return
    }

    try {
      await createTask.mutateAsync({
        file: selectedFile,
        options,
      })
      toast.success('分析任务已创建')
      setSelectedFile(null)
      setTimeout(() => navigate('/tasks'), 100)
    } catch {
      toast.error('创建任务失败')
    }
  }

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  const threatCount =
    (stats?.verdict_stats?.malicious ?? 0) +
    (stats?.verdict_stats?.suspicious ?? 0)

  return (
    <div className="mx-auto max-w-5xl space-y-6 p-6">
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardContent className="p-5">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">总扫描数</p>
                <p className="mt-1 text-2xl font-semibold">
                  {stats?.database_stats?.total ?? 0}
                </p>
              </div>
              <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-primary/10">
                <BarChart3 className="h-6 w-6 text-primary" />
              </div>
            </div>
            <div className="mt-3 flex items-center text-sm">
              <span className="flex items-center text-green-600">
                <TrendingUp className="mr-1 h-4 w-4" />
                12%
              </span>
              <span className="ml-2 text-muted-foreground">较上周</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-5">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">检测威胁</p>
                <p className="mt-1 text-2xl font-semibold">{threatCount}</p>
              </div>
              <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-red-500/10">
                <AlertTriangle className="h-6 w-6 text-red-500" />
              </div>
            </div>
            <div className="mt-3 flex items-center gap-3 text-sm">
              <span className="flex items-center text-red-600">
                <span className="mr-1.5 h-2 w-2 rounded-full bg-red-500" />
                恶意 {stats?.verdict_stats?.malicious ?? 0}
              </span>
              <span className="flex items-center text-amber-600">
                <span className="mr-1.5 h-2 w-2 rounded-full bg-amber-500" />
                可疑 {stats?.verdict_stats?.suspicious ?? 0}
              </span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-5">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">进行中</p>
                <p className="mt-1 text-2xl font-semibold">
                  {stats?.queue_stats?.pending ?? 0}
                </p>
              </div>
              <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-amber-500/10">
                <RefreshCw className="h-6 w-6 animate-spin text-amber-500" />
              </div>
            </div>
            <Button
              variant="link"
              className="mt-3 h-auto p-0 text-sm"
              onClick={() => navigate('/tasks')}
            >
              查看任务列表
              <ChevronRight className="ml-1 h-4 w-4" />
            </Button>
          </CardContent>
        </Card>
      </div>

      <Card>
        <Tabs defaultValue="file" className="w-full">
          <div className="border-b bg-muted/50">
            <TabsList className="ml-4 mt-2 h-auto gap-0 bg-transparent p-0">
              <TabsTrigger
                value="file"
                className="rounded-b-none border border-b-0 border-transparent data-[state=active]:border-border data-[state=active]:bg-background"
              >
                <FileText className="mr-2 h-4 w-4" />
                文件上传
              </TabsTrigger>
              <TabsTrigger
                value="url"
                className="rounded-b-none border border-b-0 border-transparent data-[state=active]:border-border data-[state=active]:bg-background"
              >
                <LinkIcon className="mr-2 h-4 w-4" />
                URL 分析
              </TabsTrigger>
              <TabsTrigger
                value="hash"
                className="rounded-b-none border border-b-0 border-transparent data-[state=active]:border-border data-[state=active]:bg-background"
              >
                <Hash className="mr-2 h-4 w-4" />
                哈希搜索
              </TabsTrigger>
            </TabsList>
          </div>

          <CardContent className="p-6">
            <TabsContent value="file" className="m-0">
              {!selectedFile ? (
                <div
                  className={`cursor-pointer rounded-xl border-2 border-dashed p-8 text-center transition-colors ${
                    isDragging
                      ? 'border-primary bg-primary/5'
                      : 'border-border hover:border-primary hover:bg-primary/5'
                  }`}
                  onDragOver={(e) => {
                    e.preventDefault()
                    setIsDragging(true)
                  }}
                  onDragLeave={() => setIsDragging(false)}
                  onDrop={handleDrop}
                  onClick={() =>
                    document.getElementById('file-input')?.click()
                  }
                >
                  <div className="flex flex-col items-center">
                    <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-primary/10">
                      <Upload className="h-8 w-8 text-primary" />
                    </div>
                    <p className="mb-1 font-medium">拖拽文件到此处，或点击选择</p>
                    <p className="text-sm text-muted-foreground">
                      支持 PE、ELF、Mach-O、APK、脚本等格式，最大 64MB
                    </p>
                  </div>
                  <input
                    type="file"
                    id="file-input"
                    className="hidden"
                    onChange={handleFileSelect}
                  />
                </div>
              ) : (
                <div className="mb-4 rounded-lg bg-muted/50 p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-muted">
                        <FileText className="h-5 w-5 text-muted-foreground" />
                      </div>
                      <div>
                        <p className="font-medium">{selectedFile.name}</p>
                        <p className="text-sm text-muted-foreground">
                          {formatFileSize(selectedFile.size)}
                        </p>
                      </div>
                    </div>
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => setSelectedFile(null)}
                    >
                      <span className="sr-only">移除文件</span>×
                    </Button>
                  </div>
                </div>
              )}
            </TabsContent>

            <TabsContent value="url" className="m-0">
              <div className="space-y-2">
                <Label>URL 地址</Label>
                <Input placeholder="https://example.com/suspicious-file.exe" />
                <p className="text-xs text-muted-foreground">
                  输入完整的 URL 地址，系统将下载并分析目标文件
                </p>
              </div>
            </TabsContent>

            <TabsContent value="hash" className="m-0">
              <div className="space-y-2">
                <Label>文件哈希</Label>
                <Input
                  placeholder="输入 MD5、SHA1 或 SHA256 哈希值"
                  className="font-mono"
                />
                <p className="text-xs text-muted-foreground">
                  搜索已分析的文件或从威胁情报源获取信息
                </p>
              </div>
            </TabsContent>

            <Collapsible
              open={advancedOpen}
              onOpenChange={setAdvancedOpen}
              className="mt-4"
            >
              <CollapsibleTrigger asChild>
                <Button variant="ghost" className="gap-2 p-0">
                  <ChevronRight
                    className={`h-4 w-4 transition-transform ${
                      advancedOpen ? 'rotate-90' : ''
                    }`}
                  />
                  高级分析选项
                </Button>
              </CollapsibleTrigger>
              <CollapsibleContent className="mt-4 space-y-4 rounded-lg bg-muted/50 p-4">
                <div>
                  <h4 className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    静态分析
                  </h4>
                  <div className="grid gap-3 md:grid-cols-3">
                    <Label className="flex cursor-pointer items-center gap-3 rounded-lg border bg-background p-3 hover:bg-muted/50">
                      <Switch
                        checked={options.enable_capa}
                        onCheckedChange={(checked) =>
                          setOptions((o) => ({ ...o, enable_capa: checked }))
                        }
                      />
                      <div>
                        <span className="text-sm font-medium">CAPA 分析</span>
                        <p className="text-xs text-muted-foreground">能力检测</p>
                      </div>
                    </Label>
                    <Label className="flex cursor-pointer items-center gap-3 rounded-lg border bg-background p-3 hover:bg-muted/50">
                      <Switch
                        checked={options.enable_strings}
                        onCheckedChange={(checked) =>
                          setOptions((o) => ({ ...o, enable_strings: checked }))
                        }
                      />
                      <div>
                        <span className="text-sm font-medium">字符串提取</span>
                        <p className="text-xs text-muted-foreground">
                          敏感字符串
                        </p>
                      </div>
                    </Label>
                    <Label className="flex cursor-pointer items-center gap-3 rounded-lg border bg-background p-3 hover:bg-muted/50">
                      <Switch
                        checked={options.enable_yara}
                        onCheckedChange={(checked) =>
                          setOptions((o) => ({ ...o, enable_yara: checked }))
                        }
                      />
                      <div>
                        <span className="text-sm font-medium">YARA 扫描</span>
                        <p className="text-xs text-muted-foreground">规则匹配</p>
                      </div>
                    </Label>
                  </div>
                </div>

                <div>
                  <h4 className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    动态分析
                  </h4>
                  <div className="grid gap-3 md:grid-cols-2">
                    <Label className="flex cursor-pointer items-center gap-3 rounded-lg border bg-background p-3 hover:bg-muted/50">
                      <Switch
                        checked={options.enable_dynamic}
                        onCheckedChange={(checked) =>
                          setOptions((o) => ({ ...o, enable_dynamic: checked }))
                        }
                      />
                      <div>
                        <span className="text-sm font-medium">沙箱执行</span>
                        <p className="text-xs text-muted-foreground">
                          行为监控与系统调用追踪
                        </p>
                      </div>
                    </Label>
                  </div>
                </div>

                <div>
                  <h4 className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    深度分析
                  </h4>
                  <Label className="flex cursor-pointer items-center gap-3 rounded-lg border bg-background p-3 hover:bg-muted/50">
                    <Switch
                      checked={options.enable_ghidra}
                      onCheckedChange={(checked) =>
                        setOptions((o) => ({ ...o, enable_ghidra: checked }))
                      }
                    />
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium">
                          Ghidra 逆向分析
                        </span>
                        <span className="rounded bg-primary/10 px-1.5 py-0.5 text-xs text-primary">
                          AI 增强
                        </span>
                      </div>
                      <p className="text-xs text-muted-foreground">
                        反编译、函数分析、恶意行为识别
                      </p>
                    </div>
                  </Label>
                </div>
              </CollapsibleContent>
            </Collapsible>

            <Button
              className="mt-4 w-full"
              size="lg"
              onClick={handleSubmit}
              disabled={createTask.isPending}
            >
              <Search className="mr-2 h-5 w-5" />
              {createTask.isPending ? '正在创建...' : '开始分析'}
            </Button>
          </CardContent>
        </Tabs>
      </Card>

      <Card>
        <CardContent className="p-6">
          <h2 className="mb-4 text-lg font-semibold">分析流程</h2>
          <div className="grid gap-4 md:grid-cols-4">
            {[
              {
                step: 1,
                title: '文件识别',
                icon: Hash,
                items: ['哈希计算', '文件类型检测'],
              },
              {
                step: 2,
                title: '深度分析',
                icon: Cpu,
                items: ['CAPA / YARA', '动态分析'],
              },
              {
                step: 3,
                title: 'Ghidra 分析',
                icon: Code,
                items: ['反编译分析', 'AI 函数分析'],
              },
              {
                step: 4,
                title: '报告生成',
                icon: FileOutput,
                items: ['综合评估', 'IOC 提取'],
              },
            ].map((phase, index) => (
              <div key={phase.step} className="relative">
                <div className="rounded-lg bg-muted/50 p-4">
                  <div className="mb-3 flex items-center gap-2">
                    <div className="flex h-6 w-6 items-center justify-center rounded-full bg-primary text-xs font-medium text-primary-foreground">
                      {phase.step}
                    </div>
                    <span className="font-medium">{phase.title}</span>
                  </div>
                  <ul className="space-y-2 text-sm text-muted-foreground">
                    {phase.items.map((item) => (
                      <li key={item} className="flex items-center gap-2">
                        <phase.icon className="h-4 w-4" />
                        {item}
                      </li>
                    ))}
                  </ul>
                </div>
                {index < 3 && (
                  <div className="absolute -right-2 top-1/2 hidden -translate-y-1/2 md:block">
                    <ChevronRight className="h-4 w-4 text-muted-foreground" />
                  </div>
                )}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
