import { Layers } from 'lucide-react';

interface FunctionClassViewProps {
  data: {
    classifications?: Record<string, string[]>;
    summary?: Record<string, number>;
  };
}

const CATEGORY_CONFIG: Record<string, { color: string; bgColor: string; description: string }> = {
  network: { 
    color: 'text-blue-400', 
    bgColor: 'bg-blue-500/10 border-blue-500/30',
    description: 'Network communication functions'
  },
  file: { 
    color: 'text-emerald-400', 
    bgColor: 'bg-emerald-500/10 border-emerald-500/30',
    description: 'File system operations'
  },
  process: { 
    color: 'text-purple-400', 
    bgColor: 'bg-purple-500/10 border-purple-500/30',
    description: 'Process management'
  },
  memory: { 
    color: 'text-orange-400', 
    bgColor: 'bg-orange-500/10 border-orange-500/30',
    description: 'Memory manipulation'
  },
  crypto: { 
    color: 'text-pink-400', 
    bgColor: 'bg-pink-500/10 border-pink-500/30',
    description: 'Cryptographic operations'
  },
  system: { 
    color: 'text-cyan-400', 
    bgColor: 'bg-cyan-500/10 border-cyan-500/30',
    description: 'System calls and info'
  },
  string: { 
    color: 'text-yellow-400', 
    bgColor: 'bg-yellow-500/10 border-yellow-500/30',
    description: 'String manipulation'
  },
  debug: { 
    color: 'text-red-400', 
    bgColor: 'bg-red-500/10 border-red-500/30',
    description: 'Debugging and anti-analysis'
  },
  other: { 
    color: 'text-slate-400', 
    bgColor: 'bg-slate-500/10 border-slate-500/30',
    description: 'Other functions'
  },
};

export function FunctionClassView({ data }: FunctionClassViewProps) {
  const classifications = data.classifications || {};
  const categories = Object.entries(classifications).filter(([, funcs]) => funcs && funcs.length > 0);

  if (categories.length === 0) {
    return (
      <div className="text-center py-6 text-slate-500">
        <Layers className="w-8 h-8 mx-auto mb-2 opacity-50" />
        <p>No function classifications available</p>
        <p className="text-xs mt-1">Binary may be statically linked</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {categories.map(([category, functions]) => {
        const config = CATEGORY_CONFIG[category.toLowerCase()] || CATEGORY_CONFIG.other;
        
        return (
          <div key={category} className={`rounded-lg border p-4 ${config.bgColor}`}>
            <div className="flex items-center justify-between mb-2">
              <div>
                <span className={`font-medium capitalize ${config.color}`}>{category}</span>
                <p className="text-xs text-slate-500">{config.description}</p>
              </div>
              <span className="text-xs bg-slate-800 px-2 py-0.5 rounded-full text-slate-400">
                {functions.length}
              </span>
            </div>
            <div className="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto">
              {functions.slice(0, 30).map((func, i) => (
                <span 
                  key={i} 
                  className="text-xs font-mono bg-slate-900/50 text-slate-300 px-2 py-1 rounded"
                >
                  {func}
                </span>
              ))}
              {functions.length > 30 && (
                <span className="text-xs text-slate-500 px-2 py-1">
                  +{functions.length - 30} more
                </span>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
