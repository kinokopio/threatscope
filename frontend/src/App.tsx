import { useState, useEffect } from 'react'
import { BrowserRouter, Routes, Route, useLocation } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Toaster } from '@/components/ui/sonner'
import { TooltipProvider } from '@/components/ui/tooltip'
import {
  SidebarProvider,
  SidebarInset,
  SidebarTrigger,
} from '@/components/ui/sidebar'
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from '@/components/ui/breadcrumb'
import { Separator } from '@/components/ui/separator'
import { AppSidebar } from '@/components/layout/app-sidebar'
import { HomePage } from '@/pages/home'
import { TasksPage } from '@/pages/tasks'
import { HistoryPage } from '@/pages/history'
import { ReportPage } from '@/pages/report'
import { MCPPage } from '@/pages/mcp'
import { SkillsPage } from '@/pages/skills'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5000,
      retry: 1,
    },
  },
})

const routeTitles: Record<string, string> = {
  '/': '首页',
  '/tasks': '任务列表',
  '/history': '分析历史',
  '/mcp': 'MCP 工具',
  '/skills': '技能管理',
}

function PageBreadcrumb() {
  const location = useLocation()
  const isReportPage = location.pathname.startsWith('/report/')
  const title = isReportPage
    ? '分析报告'
    : routeTitles[location.pathname] || '页面'

  return (
    <Breadcrumb>
      <BreadcrumbList>
        <BreadcrumbItem className="hidden md:block">
          <BreadcrumbLink href="/">ThreatScope</BreadcrumbLink>
        </BreadcrumbItem>
        <BreadcrumbSeparator className="hidden md:block" />
        {isReportPage && (
          <>
            <BreadcrumbItem className="hidden md:block">
              <BreadcrumbLink href="/history">分析历史</BreadcrumbLink>
            </BreadcrumbItem>
            <BreadcrumbSeparator className="hidden md:block" />
          </>
        )}
        <BreadcrumbItem>
          <BreadcrumbPage>{title}</BreadcrumbPage>
        </BreadcrumbItem>
      </BreadcrumbList>
    </Breadcrumb>
  )
}

function NotFoundPage() {
  return (
    <div className="flex h-[50vh] items-center justify-center">
      <div className="text-center">
        <h1 className="text-4xl font-bold text-muted-foreground">404</h1>
        <p className="mt-2 text-lg">页面未找到</p>
      </div>
    </div>
  )
}

function AppLayout() {
  const [theme, setTheme] = useState<'light' | 'dark'>('light')

  useEffect(() => {
    const root = document.documentElement
    if (theme === 'dark') {
      root.classList.add('dark')
    } else {
      root.classList.remove('dark')
    }
  }, [theme])

  const toggleTheme = () => {
    setTheme((t) => (t === 'light' ? 'dark' : 'light'))
  }

  return (
    <SidebarProvider>
      <AppSidebar theme={theme} onThemeToggle={toggleTheme} />
      <SidebarInset>
        <header className="flex h-16 shrink-0 items-center gap-2 border-b px-4">
          <SidebarTrigger className="-ml-1" />
          <Separator orientation="vertical" className="mr-2 h-4" />
          <PageBreadcrumb />
        </header>
        <main className="flex-1 overflow-auto">
          <Routes>
            <Route path="/" element={<HomePage />} />
            <Route path="/tasks" element={<TasksPage />} />
            <Route path="/history" element={<HistoryPage />} />
            <Route path="/report/:id" element={<ReportPage />} />
            <Route path="/mcp" element={<MCPPage />} />
            <Route path="/skills" element={<SkillsPage />} />
            <Route path="*" element={<NotFoundPage />} />
          </Routes>
        </main>
      </SidebarInset>
    </SidebarProvider>
  )
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <BrowserRouter>
          <AppLayout />
        </BrowserRouter>
        <Toaster />
      </TooltipProvider>
    </QueryClientProvider>
  )
}
