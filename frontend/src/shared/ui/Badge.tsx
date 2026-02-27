import { memo } from 'react';

export type BadgeVariant = 'default' | 'success' | 'warning' | 'danger' | 'info' | 'purple';

interface BadgeProps {
  children: React.ReactNode;
  variant?: BadgeVariant;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

const VARIANT_STYLES: Record<BadgeVariant, string> = {
  default: 'bg-slate-700 text-slate-200 border-slate-600',
  success: 'bg-emerald-900/30 text-emerald-400 border-emerald-800',
  warning: 'bg-yellow-900/30 text-yellow-400 border-yellow-800',
  danger: 'bg-red-900/30 text-red-400 border-red-800',
  info: 'bg-cyan-900/30 text-cyan-400 border-cyan-800',
  purple: 'bg-purple-900/30 text-purple-400 border-purple-800',
};

const SIZE_STYLES = {
  sm: 'px-2 py-0.5 text-xs',
  md: 'px-3 py-1 text-sm',
  lg: 'px-4 py-1.5 text-base',
};

export const Badge = memo(function Badge({
  children,
  variant = 'default',
  size = 'md',
  className = '',
}: BadgeProps) {
  return (
    <span
      className={`inline-flex items-center rounded-full border font-medium ${VARIANT_STYLES[variant]} ${SIZE_STYLES[size]} ${className}`}
    >
      {children}
    </span>
  );
});

export default Badge;
