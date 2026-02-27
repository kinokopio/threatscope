import { memo } from 'react';

interface CardProps {
  children: React.ReactNode;
  className?: string;
  padding?: 'none' | 'sm' | 'md' | 'lg';
  hover?: boolean;
  onClick?: () => void;
}

const PADDING_STYLES = {
  none: '',
  sm: 'p-4',
  md: 'p-6',
  lg: 'p-8',
};

export const Card = memo(function Card({
  children,
  className = '',
  padding = 'md',
  hover = false,
  onClick,
}: CardProps) {
  const baseStyles = 'bg-slate-800 rounded-xl border border-slate-700 shadow-lg';
  const hoverStyles = hover ? 'hover:border-cyan-500/50 transition-all cursor-pointer' : '';
  const paddingStyles = PADDING_STYLES[padding];

  return (
    <div
      className={`${baseStyles} ${hoverStyles} ${paddingStyles} ${className}`}
      onClick={onClick}
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
    >
      {children}
    </div>
  );
});

// Card Header component
interface CardHeaderProps {
  children: React.ReactNode;
  className?: string;
  icon?: React.ReactNode;
  action?: React.ReactNode;
}

export const CardHeader = memo(function CardHeader({
  children,
  className = '',
  icon,
  action,
}: CardHeaderProps) {
  return (
    <div className={`flex items-center justify-between mb-4 ${className}`}>
      <h2 className="text-2xl font-bold text-emerald-400 flex items-center">
        {icon && <span className="mr-2">{icon}</span>}
        {children}
      </h2>
      {action}
    </div>
  );
});

// Card Content component
interface CardContentProps {
  children: React.ReactNode;
  className?: string;
}

export const CardContent = memo(function CardContent({
  children,
  className = '',
}: CardContentProps) {
  return <div className={className}>{children}</div>;
});

export default Card;
