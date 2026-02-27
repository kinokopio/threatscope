import { memo } from 'react';
import { Loader2 } from 'lucide-react';

interface LoadingProps {
  message?: string;
  size?: 'sm' | 'md' | 'lg';
  fullScreen?: boolean;
}

const SIZE_MAP = {
  sm: { icon: 'w-6 h-6', text: 'text-sm' },
  md: { icon: 'w-12 h-12', text: 'text-2xl' },
  lg: { icon: 'w-16 h-16', text: 'text-3xl' },
};

export const Loading = memo(function Loading({
  message = 'Loading...',
  size = 'md',
  fullScreen = false,
}: LoadingProps) {
  const { icon, text } = SIZE_MAP[size];

  const content = (
    <div className="bg-slate-800 p-8 rounded-xl border border-slate-700 text-center">
      <Loader2 className={`animate-spin ${icon} mx-auto text-cyan-400 mb-4`} />
      <h3 className={`font-bold text-white ${text}`}>{message}</h3>
    </div>
  );

  if (fullScreen) {
    return (
      <div className="fixed inset-0 bg-slate-950/80 flex items-center justify-center z-50">
        {content}
      </div>
    );
  }

  return content;
});

interface PageLoadingProps {
  message?: string;
}

export const PageLoading = memo(function PageLoading({ message }: PageLoadingProps) {
  return (
    <div className="max-w-7xl mx-auto flex items-center justify-center min-h-[400px]">
      <Loading message={message} />
    </div>
  );
});

export default Loading;
