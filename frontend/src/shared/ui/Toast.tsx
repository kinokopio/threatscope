import { createContext, useContext, useState, useCallback, memo, type ReactNode } from 'react';
import { CheckCircle, AlertCircle, AlertTriangle, Info, X } from 'lucide-react';

type ToastType = 'success' | 'error' | 'warning' | 'info';

interface Toast {
  id: string;
  type: ToastType;
  message: string;
  duration?: number;
}

interface ToastContextValue {
  toasts: Toast[];
  addToast: (type: ToastType, message: string, duration?: number) => void;
  removeToast: (id: string) => void;
  success: (message: string) => void;
  error: (message: string) => void;
  warning: (message: string) => void;
  info: (message: string) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

export function useToast() {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error('useToast must be used within a ToastProvider');
  }
  return context;
}

const TOAST_STYLES: Record<ToastType, { bg: string; icon: typeof CheckCircle }> = {
  success: { bg: 'bg-emerald-900/90 border-emerald-700', icon: CheckCircle },
  error: { bg: 'bg-red-900/90 border-red-700', icon: AlertCircle },
  warning: { bg: 'bg-yellow-900/90 border-yellow-700', icon: AlertTriangle },
  info: { bg: 'bg-cyan-900/90 border-cyan-700', icon: Info },
};

const TOAST_ICON_COLORS: Record<ToastType, string> = {
  success: 'text-emerald-400',
  error: 'text-red-400',
  warning: 'text-yellow-400',
  info: 'text-cyan-400',
};

interface ToastItemProps {
  toast: Toast;
  onRemove: (id: string) => void;
}

const ToastItem = memo(function ToastItem({ toast, onRemove }: ToastItemProps) {
  const { bg, icon: Icon } = TOAST_STYLES[toast.type];
  const iconColor = TOAST_ICON_COLORS[toast.type];

  return (
    <div
      className={`flex items-center gap-3 px-4 py-3 rounded-lg border shadow-lg ${bg} animate-in slide-in-from-right duration-300`}
    >
      <Icon className={`w-5 h-5 ${iconColor} flex-shrink-0`} />
      <p className="text-white text-sm flex-1">{toast.message}</p>
      <button
        onClick={() => onRemove(toast.id)}
        className="text-slate-400 hover:text-white transition-colors"
      >
        <X className="w-4 h-4" />
      </button>
    </div>
  );
});

interface ToastProviderProps {
  children: ReactNode;
}

export function ToastProvider({ children }: ToastProviderProps) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const removeToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const addToast = useCallback(
    (type: ToastType, message: string, duration = 5000) => {
      const id = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
      const toast: Toast = { id, type, message, duration };

      setToasts((prev) => [...prev, toast]);

      if (duration > 0) {
        setTimeout(() => removeToast(id), duration);
      }
    },
    [removeToast]
  );

  const success = useCallback((message: string) => addToast('success', message), [addToast]);
  const error = useCallback((message: string) => addToast('error', message), [addToast]);
  const warning = useCallback((message: string) => addToast('warning', message), [addToast]);
  const info = useCallback((message: string) => addToast('info', message), [addToast]);

  return (
    <ToastContext.Provider
      value={{ toasts, addToast, removeToast, success, error, warning, info }}
    >
      {children}
      <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-sm">
        {toasts.map((toast) => (
          <ToastItem key={toast.id} toast={toast} onRemove={removeToast} />
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export default ToastProvider;
