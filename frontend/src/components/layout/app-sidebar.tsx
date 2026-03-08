import { Link, useLocation } from 'react-router-dom'
import {
  Home,
  ListTodo,
  History,
  Terminal,
  Shield,
  Moon,
  Sun,
} from 'lucide-react'
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
} from '@/components/ui/sidebar'
import { Button } from '@/components/ui/button'
import { useHealth } from '@/hooks/use-stats'
import { useTasks } from '@/hooks/use-tasks'

const navItems = [
  { title: '首页', url: '/', icon: Home },
  { title: '任务列表', url: '/tasks', icon: ListTodo, showBadge: true },
  { title: '分析历史', url: '/history', icon: History },
  { title: 'MCP 工具', url: '/mcp', icon: Terminal },
]

interface AppSidebarProps {
  theme: 'light' | 'dark'
  onThemeToggle: () => void
}

const ACTIVE_STATUSES = ['pending', 'queued', 'static_analysis', 'dynamic_analysis', 'ghidra_analysis', 'report_generation']

export function AppSidebar({ theme, onThemeToggle }: AppSidebarProps) {
  const location = useLocation()
  const { data: health } = useHealth()
  const { data: tasks } = useTasks({ limit: 50 })
  const runningCount = tasks?.filter(t => ACTIVE_STATUSES.includes(t.status)).length ?? 0

  return (
    <Sidebar>
      <SidebarHeader className="border-b border-sidebar-border">
        <div className="flex items-center gap-3 px-2 py-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary text-primary-foreground">
            <Shield className="h-5 w-5" />
          </div>
          <span className="text-lg font-semibold">ThreatScope</span>
        </div>
      </SidebarHeader>

      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupContent>
            <SidebarMenu>
              {navItems.map((item) => (
                <SidebarMenuItem key={item.title}>
                  <SidebarMenuButton
                    asChild
                    isActive={location.pathname === item.url}
                  >
                    <Link to={item.url}>
                      <item.icon className="h-5 w-5" />
                      <span>{item.title}</span>
                    </Link>
                  </SidebarMenuButton>
                  {item.showBadge && runningCount > 0 && (
                    <SidebarMenuBadge>{runningCount}</SidebarMenuBadge>
                  )}
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>

      <SidebarFooter className="border-t border-sidebar-border">
        <div className="px-2 py-2">
          <div className="mb-3 text-xs font-medium text-muted-foreground">
            系统状态
          </div>
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-sm">
              <span
                className={`h-2 w-2 rounded-full ${
                  health?.services?.api ? 'bg-green-500' : 'bg-red-500'
                }`}
              />
              <span className="text-muted-foreground">API 服务</span>
              <span
                className={`ml-auto text-xs ${
                  health?.services?.api ? 'text-green-600' : 'text-red-600'
                }`}
              >
                {health?.services?.api ? '正常' : '异常'}
              </span>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <span
                className={`h-2 w-2 rounded-full ${
                  health?.services?.ghidra_mcp ? 'bg-green-500' : 'bg-yellow-500'
                }`}
              />
              <span className="text-muted-foreground">Ghidra MCP</span>
              <span
                className={`ml-auto text-xs ${
                  health?.services?.ghidra_mcp ? 'text-green-600' : 'text-yellow-600'
                }`}
              >
                {health?.services?.ghidra_mcp ? '正常' : '离线'}
              </span>
            </div>
          </div>
        </div>

        <div className="flex items-center justify-between border-t border-sidebar-border px-2 py-2">
          <Button
            variant="ghost"
            size="icon"
            onClick={onThemeToggle}
            className="h-8 w-8"
          >
            {theme === 'dark' ? (
              <Sun className="h-4 w-4" />
            ) : (
              <Moon className="h-4 w-4" />
            )}
          </Button>
          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary/10 text-sm font-medium text-primary">
            A
          </div>
        </div>
      </SidebarFooter>
    </Sidebar>
  )
}
