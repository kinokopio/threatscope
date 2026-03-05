import { useState, useEffect, useCallback, memo } from 'react';
import { Routes, Route, Link, useLocation } from 'react-router-dom';
import { Home as HomeIcon, Clock, Shield, ListTodo, Activity } from 'lucide-react';
import Home from './pages/Home';
import History from './pages/History';
import Tasks from './pages/Tasks';
import TaskDetail from './pages/TaskDetail';
import ReportDetail from './pages/ReportDetail';
import { useTasks } from './shared/api';

const NAV_ITEMS = [
  { path: '/', label: 'Home', icon: HomeIcon },
  { path: '/tasks', label: 'Tasks', icon: ListTodo },
  { path: '/history', label: 'History', icon: Clock },
] as const;

interface NavLinkProps {
  path: string;
  label: string;
  icon: typeof HomeIcon;
  isActive: boolean;
  badge?: number;
}

const NavLink = memo(function NavLink({ path, label, icon: Icon, isActive, badge }: NavLinkProps) {
  return (
    <Link
      to={path}
      className={`relative flex items-center px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
        isActive
          ? 'bg-gradient-to-r from-emerald-500/20 to-cyan-500/20 text-white border border-emerald-500/30'
          : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
      }`}
    >
      <Icon className={`w-4 h-4 mr-2 ${isActive ? 'text-emerald-400' : ''}`} />
      {label}
      {badge !== undefined && badge > 0 && (
        <span className="ml-2 px-1.5 py-0.5 text-xs font-bold rounded-full bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
          {badge}
        </span>
      )}
    </Link>
  );
});

function App() {
  const location = useLocation();
  const [isScrolled, setIsScrolled] = useState(false);
  const [isVisible, setIsVisible] = useState(true);
  const [lastScrollY, setLastScrollY] = useState(0);
  
  const { data: tasksData } = useTasks({ refetchInterval: 10000 });
  
  const pendingCount = tasksData?.tasks?.filter(
    t => ['pending', 'queued', 'hashing', 'file_identification', 'static_analysis', 'threat_intel', 'dynamic_analysis', 'ghidra_analysis', 'report_generation'].includes(t.status)
  ).length || 0;

  useEffect(() => {
    const handleScroll = () => {
      const currentScrollY = window.scrollY;
      setIsScrolled(currentScrollY > 20);
      
      if (currentScrollY > lastScrollY && currentScrollY > 100) {
        setIsVisible(false);
      } else {
        setIsVisible(true);
      }
      
      setLastScrollY(currentScrollY);
    };

    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, [lastScrollY]);

  const isActive = useCallback((path: string) => location.pathname === path, [location.pathname]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-50 font-sans selection:bg-cyan-500/30">
      {/* Background gradient effect */}
      <div className="fixed inset-0 bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 pointer-events-none" />
      <div className="fixed top-0 left-1/4 w-96 h-96 bg-emerald-500/5 rounded-full blur-3xl pointer-events-none" />
      <div className="fixed bottom-0 right-1/4 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />
      
      {/* Navigation */}
      <nav className={`fixed left-0 right-0 z-50 transition-all duration-300 ${
        isVisible ? 'translate-y-0' : '-translate-y-full'
      }`}>
        <div className={`mx-4 mt-4 rounded-2xl bg-slate-900/80 backdrop-blur-xl border border-slate-800/50 shadow-2xl shadow-black/20 transition-all duration-300 ${
          isScrolled ? 'py-2' : 'py-3'
        }`}>
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex items-center justify-between">
            {/* Logo */}
            <Link to="/" className="flex items-center space-x-3 group">
              <div className="relative">
                <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-emerald-500 to-cyan-600 flex items-center justify-center shadow-lg shadow-emerald-500/20 group-hover:shadow-emerald-500/40 transition-shadow">
                  <Shield className="w-5 h-5 text-white" />
                </div>
                {pendingCount > 0 && (
                  <div className="absolute -top-1 -right-1 w-3 h-3 rounded-full bg-cyan-400 animate-pulse" />
                )}
              </div>
              <div className="flex flex-col">
                <span className="text-lg font-bold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-emerald-400 to-cyan-500">
                  ThreatScope
                </span>
                <span className="text-[10px] text-slate-500 -mt-1 tracking-wider uppercase">
                  Malware Analysis
                </span>
              </div>
            </Link>

            {/* Navigation Links */}
            <div className="flex items-center space-x-1 p-1 rounded-xl bg-slate-800/30 border border-slate-700/30">
              {NAV_ITEMS.map((item) => (
                <NavLink
                  key={item.path}
                  path={item.path}
                  label={item.label}
                  icon={item.icon}
                  isActive={isActive(item.path)}
                  badge={item.path === '/tasks' ? pendingCount : undefined}
                />
              ))}
            </div>

            {/* Status Indicator */}
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-800/30 border border-slate-700/30">
              <Activity className={`w-4 h-4 ${pendingCount > 0 ? 'text-cyan-400 animate-pulse' : 'text-slate-500'}`} />
              <span className="text-xs text-slate-400">
                {pendingCount > 0 ? (
                  <span className="text-cyan-400">{pendingCount} active</span>
                ) : (
                  'Idle'
                )}
              </span>
            </div>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="relative pt-28 pb-12 px-4 sm:px-6 lg:px-8">
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/tasks" element={<Tasks />} />
          <Route path="/history" element={<History />} />
          <Route path="/task/:taskId" element={<TaskDetail />} />
          <Route path="/report/:taskId" element={<ReportDetail />} />
        </Routes>
      </main>

      {/* Footer */}
      <footer className="relative border-t border-slate-800/50 py-6">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between text-xs text-slate-500">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-emerald-500/50" />
              <span>ThreatScope — AI-Powered Malware Analysis</span>
            </div>
            <div className="flex items-center gap-4">
              <span>MITRE ATT&CK Integrated</span>
              <span className="w-1 h-1 rounded-full bg-slate-700" />
              <span>Ghidra Powered</span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
