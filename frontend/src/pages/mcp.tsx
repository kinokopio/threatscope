import { useState } from 'react'
import {
  Terminal,
  Play,
  Code,
  FileSearch,
  Binary,
  Network,
  Shield,
  Cpu,
  ChevronRight,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Separator } from '@/components/ui/separator'
import { useHealth } from '@/hooks/use-stats'

interface MCPTool {
  id: string
  name: string
  description: string
  icon: React.ElementType
  category: string
  parameters: Array<{
    name: string
    type: string
    required: boolean
    description: string
  }>
}

const mcpTools: MCPTool[] = [
  {
    id: 'decompile_function',
    name: '反编译函数',
    description: '使用 Ghidra 反编译指定地址的函数',
    icon: Code,
    category: 'Ghidra',
    parameters: [
      {
        name: 'address',
        type: 'string',
        required: true,
        description: '函数地址 (如 0x401000)',
      },
    ],
  },
  {
    id: 'list_functions',
    name: '列出函数',
    description: '获取二进制文件中的所有函数列表',
    icon: FileSearch,
    category: 'Ghidra',
    parameters: [
      {
        name: 'filter',
        type: 'string',
        required: false,
        description: '函数名过滤器',
      },
    ],
  },
  {
    id: 'get_xrefs',
    name: '获取交叉引用',
    description: '获取指定地址的交叉引用',
    icon: Network,
    category: 'Ghidra',
    parameters: [
      {
        name: 'address',
        type: 'string',
        required: true,
        description: '目标地址',
      },
    ],
  },
  {
    id: 'analyze_binary',
    name: '分析二进制',
    description: '对二进制文件进行完整分析',
    icon: Binary,
    category: 'Analysis',
    parameters: [
      {
        name: 'file_path',
        type: 'string',
        required: true,
        description: '文件路径',
      },
    ],
  },
  {
    id: 'scan_yara',
    name: 'YARA 扫描',
    description: '使用 YARA 规则扫描文件',
    icon: Shield,
    category: 'Analysis',
    parameters: [
      {
        name: 'file_path',
        type: 'string',
        required: true,
        description: '文件路径',
      },
      {
        name: 'rules',
        type: 'string',
        required: false,
        description: '规则文件路径',
      },
    ],
  },
  {
    id: 'extract_strings',
    name: '提取字符串',
    description: '从二进制文件中提取字符串',
    icon: Cpu,
    category: 'Analysis',
    parameters: [
      {
        name: 'file_path',
        type: 'string',
        required: true,
        description: '文件路径',
      },
      {
        name: 'min_length',
        type: 'number',
        required: false,
        description: '最小字符串长度',
      },
    ],
  },
]

function ToolCard({
  tool,
  onSelect,
  isSelected,
}: {
  tool: MCPTool
  onSelect: () => void
  isSelected: boolean
}) {
  const Icon = tool.icon

  return (
    <Card
      className={`cursor-pointer transition-colors hover:bg-muted/50 ${
        isSelected ? 'ring-2 ring-primary' : ''
      }`}
      onClick={onSelect}
    >
      <CardContent className="p-4">
        <div className="flex items-start gap-3">
          <div className="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-lg bg-primary/10">
            <Icon className="h-5 w-5 text-primary" />
          </div>
          <div className="min-w-0 flex-1">
            <div className="mb-1 flex items-center gap-2">
              <h3 className="font-medium">{tool.name}</h3>
              <Badge variant="outline" className="text-xs">
                {tool.category}
              </Badge>
            </div>
            <p className="text-sm text-muted-foreground">{tool.description}</p>
          </div>
          <ChevronRight className="h-5 w-5 text-muted-foreground" />
        </div>
      </CardContent>
    </Card>
  )
}

function ToolExecutor({
  tool,
  onClose,
}: {
  tool: MCPTool
  onClose: () => void
}) {
  const [params, setParams] = useState<Record<string, string>>({})
  const [result, setResult] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(false)

  const handleExecute = async () => {
    setIsLoading(true)
    setResult(null)

    await new Promise((resolve) => setTimeout(resolve, 1500))

    setResult(
      JSON.stringify(
        {
          status: 'success',
          tool: tool.id,
          parameters: params,
          result: {
            message: `${tool.name} 执行完成`,
            data: '示例输出数据...',
          },
        },
        null,
        2
      )
    )
    setIsLoading(false)
  }

  const Icon = tool.icon

  return (
    <Card>
      <CardHeader className="border-b">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
            <Icon className="h-5 w-5 text-primary" />
          </div>
          <div>
            <CardTitle className="text-lg">{tool.name}</CardTitle>
            <p className="text-sm text-muted-foreground">{tool.description}</p>
          </div>
        </div>
      </CardHeader>
      <CardContent className="p-6">
        <div className="space-y-4">
          <div>
            <h4 className="mb-3 text-sm font-medium">参数</h4>
            <div className="space-y-4">
              {tool.parameters.map((param) => (
                <div key={param.name}>
                  <Label className="mb-1.5 flex items-center gap-2">
                    {param.name}
                    {param.required && (
                      <span className="text-destructive">*</span>
                    )}
                  </Label>
                  <Input
                    placeholder={param.description}
                    value={params[param.name] || ''}
                    onChange={(e) =>
                      setParams((p) => ({ ...p, [param.name]: e.target.value }))
                    }
                  />
                  <p className="mt-1 text-xs text-muted-foreground">
                    {param.description}
                  </p>
                </div>
              ))}
            </div>
          </div>

          <div className="flex gap-2">
            <Button onClick={handleExecute} disabled={isLoading}>
              <Play className="mr-2 h-4 w-4" />
              {isLoading ? '执行中...' : '执行'}
            </Button>
            <Button variant="outline" onClick={onClose}>
              取消
            </Button>
          </div>

          {result && (
            <>
              <Separator />
              <div>
                <h4 className="mb-3 text-sm font-medium">执行结果</h4>
                <ScrollArea className="h-[200px] rounded-lg border bg-muted/50">
                  <pre className="p-4 font-mono text-sm">{result}</pre>
                </ScrollArea>
              </div>
            </>
          )}
        </div>
      </CardContent>
    </Card>
  )
}

export function MCPPage() {
  const { data: health } = useHealth()
  const [selectedTool, setSelectedTool] = useState<MCPTool | null>(null)

  const ghidraTools = mcpTools.filter((t) => t.category === 'Ghidra')
  const analysisTools = mcpTools.filter((t) => t.category === 'Analysis')

  return (
    <div className="mx-auto max-w-6xl space-y-6 p-6">
      <Card>
        <CardContent className="p-4">
          <div className="flex items-center gap-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-primary/10">
              <Terminal className="h-6 w-6 text-primary" />
            </div>
            <div className="flex-1">
              <h2 className="text-lg font-semibold">MCP 工具</h2>
              <p className="text-sm text-muted-foreground">
                通过 Model Context Protocol 调用 Ghidra 和分析工具
              </p>
            </div>
            <div className="flex items-center gap-2">
              <span
                className={`h-2 w-2 rounded-full ${
                  health?.services?.ghidra_mcp ? 'bg-green-500' : 'bg-yellow-500'
                }`}
              />
              <span className="text-sm text-muted-foreground">
                Ghidra MCP: {health?.services?.ghidra_mcp ? '已连接' : '离线'}
              </span>
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <div className="space-y-6">
          <div>
            <h3 className="mb-3 text-lg font-semibold">Ghidra 工具</h3>
            <div className="space-y-3">
              {ghidraTools.map((tool) => (
                <ToolCard
                  key={tool.id}
                  tool={tool}
                  onSelect={() => setSelectedTool(tool)}
                  isSelected={selectedTool?.id === tool.id}
                />
              ))}
            </div>
          </div>

          <div>
            <h3 className="mb-3 text-lg font-semibold">分析工具</h3>
            <div className="space-y-3">
              {analysisTools.map((tool) => (
                <ToolCard
                  key={tool.id}
                  tool={tool}
                  onSelect={() => setSelectedTool(tool)}
                  isSelected={selectedTool?.id === tool.id}
                />
              ))}
            </div>
          </div>
        </div>

        <div>
          {selectedTool ? (
            <ToolExecutor
              tool={selectedTool}
              onClose={() => setSelectedTool(null)}
            />
          ) : (
            <Card>
              <CardContent className="flex h-[400px] items-center justify-center">
                <div className="text-center">
                  <Terminal className="mx-auto mb-4 h-12 w-12 text-muted-foreground" />
                  <h3 className="mb-2 text-lg font-medium">选择工具</h3>
                  <p className="text-muted-foreground">
                    从左侧选择一个工具开始使用
                  </p>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}
