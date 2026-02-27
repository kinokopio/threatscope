import { memo } from 'react';

interface SkeletonProps {
  className?: string;
  variant?: 'text' | 'circular' | 'rectangular';
  width?: string | number;
  height?: string | number;
  animation?: 'pulse' | 'wave' | 'none';
}

export const Skeleton = memo(function Skeleton({
  className = '',
  variant = 'text',
  width,
  height,
  animation = 'pulse',
}: SkeletonProps) {
  const baseStyles = 'bg-slate-700';
  
  const variantStyles = {
    text: 'rounded',
    circular: 'rounded-full',
    rectangular: 'rounded-lg',
  };

  const animationStyles = {
    pulse: 'animate-pulse',
    wave: 'animate-shimmer',
    none: '',
  };

  const style: React.CSSProperties = {
    width: width ?? (variant === 'text' ? '100%' : undefined),
    height: height ?? (variant === 'text' ? '1em' : undefined),
  };

  return (
    <div
      className={`${baseStyles} ${variantStyles[variant]} ${animationStyles[animation]} ${className}`}
      style={style}
    />
  );
});

// Skeleton group for common patterns
interface SkeletonGroupProps {
  lines?: number;
  className?: string;
}

export const SkeletonText = memo(function SkeletonText({
  lines = 3,
  className = '',
}: SkeletonGroupProps) {
  return (
    <div className={`space-y-2 ${className}`}>
      {Array.from({ length: lines }).map((_, i) => (
        <Skeleton
          key={i}
          variant="text"
          width={i === lines - 1 ? '60%' : '100%'}
          height="0.875rem"
        />
      ))}
    </div>
  );
});

export const SkeletonCard = memo(function SkeletonCard({ className = '' }: { className?: string }) {
  return (
    <div className={`bg-slate-800 rounded-xl border border-slate-700 p-6 ${className}`}>
      <div className="flex items-center gap-4 mb-4">
        <Skeleton variant="circular" width={48} height={48} />
        <div className="flex-1">
          <Skeleton variant="text" width="60%" height="1.25rem" className="mb-2" />
          <Skeleton variant="text" width="40%" height="0.875rem" />
        </div>
      </div>
      <SkeletonText lines={3} />
    </div>
  );
});

export default Skeleton;
