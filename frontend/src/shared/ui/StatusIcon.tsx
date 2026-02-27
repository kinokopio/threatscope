import { memo } from 'react';
import {
  CheckCircle2,
  Loader2,
  AlertCircle,
  Circle,
  SkipForward,
  AlertTriangle,
  HelpCircle,
} from 'lucide-react';
import type { StepStatus } from '../types';

interface StatusIconProps {
  status: StepStatus;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

const SIZE_MAP = {
  sm: 'w-4 h-4',
  md: 'w-5 h-5',
  lg: 'w-6 h-6',
};

export const StepStatusIcon = memo(function StepStatusIcon({
  status,
  size = 'md',
  className = '',
}: StatusIconProps) {
  const sizeClass = SIZE_MAP[size];

  switch (status) {
    case 'completed':
      return <CheckCircle2 className={`${sizeClass} text-emerald-400 ${className}`} />;
    case 'running':
      return <Loader2 className={`${sizeClass} text-cyan-400 animate-spin ${className}`} />;
    case 'failed':
      return <AlertCircle className={`${sizeClass} text-red-400 ${className}`} />;
    case 'skipped':
      return <SkipForward className={`${sizeClass} text-slate-500 ${className}`} />;
    default:
      return <Circle className={`${sizeClass} text-slate-600 ${className}`} />;
  }
});

// Verdict icon for malware analysis results
export type VerdictType = 'malicious' | 'suspicious' | 'benign' | 'unknown';

interface VerdictIconProps {
  verdict: VerdictType | string | undefined;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

export const VerdictIcon = memo(function VerdictIcon({
  verdict,
  size = 'md',
  className = '',
}: VerdictIconProps) {
  const sizeClass = SIZE_MAP[size];

  switch (verdict) {
    case 'malicious':
      return <AlertCircle className={`${sizeClass} text-red-400 ${className}`} />;
    case 'suspicious':
      return <AlertTriangle className={`${sizeClass} text-yellow-400 ${className}`} />;
    case 'benign':
      return <CheckCircle2 className={`${sizeClass} text-emerald-400 ${className}`} />;
    default:
      return <HelpCircle className={`${sizeClass} text-slate-400 ${className}`} />;
  }
});

// Loading spinner
interface SpinnerProps {
  size?: 'sm' | 'md' | 'lg' | 'xl';
  className?: string;
}

const SPINNER_SIZE_MAP = {
  sm: 'w-4 h-4',
  md: 'w-6 h-6',
  lg: 'w-8 h-8',
  xl: 'w-12 h-12',
};

export const Spinner = memo(function Spinner({ size = 'md', className = '' }: SpinnerProps) {
  return (
    <Loader2
      className={`${SPINNER_SIZE_MAP[size]} text-cyan-400 animate-spin ${className}`}
    />
  );
});

export default StepStatusIcon;
