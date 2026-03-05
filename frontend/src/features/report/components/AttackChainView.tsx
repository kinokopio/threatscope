import { useMemo } from 'react';
import { ArrowRight, Circle, AlertTriangle, Zap, Server, Key, Link2, Activity, Terminal } from 'lucide-react';

interface AttackStep {
  name: string;
  address?: string;
  description: string;
  category: 'entry' | 'init' | 'crypto' | 'network' | 'heartbeat' | 'command' | 'execution';
}

interface AttackChainViewProps {
  attackChain: string;
}

const categoryConfig: Record<AttackStep['category'], { icon: React.ReactNode; color: string; bgColor: string }> = {
  entry: { icon: <Circle className="w-4 h-4" />, color: 'text-emerald-400', bgColor: 'bg-emerald-500/20 border-emerald-500/50' },
  init: { icon: <Zap className="w-4 h-4" />, color: 'text-blue-400', bgColor: 'bg-blue-500/20 border-blue-500/50' },
  crypto: { icon: <Key className="w-4 h-4" />, color: 'text-purple-400', bgColor: 'bg-purple-500/20 border-purple-500/50' },
  network: { icon: <Server className="w-4 h-4" />, color: 'text-orange-400', bgColor: 'bg-orange-500/20 border-orange-500/50' },
  heartbeat: { icon: <Activity className="w-4 h-4" />, color: 'text-cyan-400', bgColor: 'bg-cyan-500/20 border-cyan-500/50' },
  command: { icon: <Link2 className="w-4 h-4" />, color: 'text-yellow-400', bgColor: 'bg-yellow-500/20 border-yellow-500/50' },
  execution: { icon: <Terminal className="w-4 h-4" />, color: 'text-red-400', bgColor: 'bg-red-500/20 border-red-500/50' },
};

function categorizeStep(name: string, description: string): AttackStep['category'] {
  const lowerName = name.toLowerCase();
  const lowerDesc = description.toLowerCase();
  
  if (lowerName.includes('entry') || lowerName.includes('main') || lowerName.includes('start')) return 'entry';
  if (lowerName.includes('init') || lowerName.includes('初始化')) return 'init';
  if (lowerName.includes('key') || lowerName.includes('session') || lowerName.includes('密钥') || lowerName.includes('crypto')) return 'crypto';
  if (lowerName.includes('connect') || lowerName.includes('c2') || lowerDesc.includes('连接') || lowerDesc.includes('服务器')) return 'network';
  if (lowerName.includes('heartbeat') || lowerName.includes('心跳') || lowerName.includes('timer')) return 'heartbeat';
  if (lowerName.includes('handle') || lowerName.includes('handler') || lowerName.includes('msg') || lowerDesc.includes('命令') || lowerDesc.includes('分发')) return 'command';
  if (lowerName.includes('task_') || lowerName.includes('exec') || lowerDesc.includes('执行') || lowerDesc.includes('恶意')) return 'execution';
  
  return 'command';
}

function parseAttackChain(chainText: string): AttackStep[] {
  const steps: AttackStep[] = [];
  
  // Split by → or ->
  const parts = chainText.split(/\s*(?:→|->)\s*/);
  
  for (const part of parts) {
    if (!part.trim()) continue;
    
    // Try to extract function name and address: "func_name (0x00123456) description"
    const addressMatch = part.match(/^([^\(]+)\s*\(0x([0-9a-fA-F]+)\)\s*(.*)/);
    
    if (addressMatch) {
      const [, name, address, description] = addressMatch;
      steps.push({
        name: name.trim(),
        address: `0x${address}`,
        description: description.trim() || name.trim(),
        category: categorizeStep(name, description),
      });
    } else {
      // No address, just name and possibly description
      const spaceIdx = part.indexOf(' ');
      if (spaceIdx > 0 && spaceIdx < 30) {
        const name = part.substring(0, spaceIdx);
        const description = part.substring(spaceIdx + 1);
        steps.push({
          name: name.trim(),
          description: description.trim() || name.trim(),
          category: categorizeStep(name, description),
        });
      } else {
        steps.push({
          name: part.trim(),
          description: part.trim(),
          category: categorizeStep(part, ''),
        });
      }
    }
  }
  
  return steps;
}

function StepCard({ step, index, isLast }: { step: AttackStep; index: number; isLast: boolean }) {
  const config = categoryConfig[step.category];
  
  return (
    <div className="flex items-start gap-3">
      <div className="flex flex-col items-center">
        <div className={`w-10 h-10 rounded-full border-2 flex items-center justify-center ${config.bgColor} ${config.color}`}>
          {config.icon}
        </div>
        {!isLast && (
          <div className="w-0.5 h-8 bg-gradient-to-b from-slate-500 to-slate-700 my-1" />
        )}
      </div>
      
      <div className={`flex-1 p-3 rounded-lg border ${config.bgColor} mb-2`}>
        <div className="flex items-center gap-2 mb-1">
          <span className="text-xs text-slate-500 font-mono">#{index + 1}</span>
          <span className={`font-semibold ${config.color}`}>{step.name}</span>
          {step.address && (
            <span className="text-xs font-mono text-slate-500 bg-slate-800 px-1.5 py-0.5 rounded">
              {step.address}
            </span>
          )}
        </div>
        {step.description && step.description !== step.name && (
          <p className="text-sm text-slate-300">{step.description}</p>
        )}
      </div>
    </div>
  );
}

function HorizontalFlow({ steps }: { steps: AttackStep[] }) {
  return (
    <div className="flex items-center gap-2 overflow-x-auto pb-4">
      {steps.map((step, idx) => {
        const config = categoryConfig[step.category];
        return (
          <div key={idx} className="flex items-center">
            <div className={`flex-shrink-0 p-3 rounded-lg border ${config.bgColor} min-w-[140px] max-w-[200px]`}>
              <div className="flex items-center gap-2 mb-1">
                <span className={config.color}>{config.icon}</span>
                <span className={`font-semibold text-sm ${config.color} truncate`}>{step.name}</span>
              </div>
              {step.address && (
                <span className="text-[10px] font-mono text-slate-500 block">{step.address}</span>
              )}
            </div>
            {idx < steps.length - 1 && (
              <ArrowRight className="w-5 h-5 text-slate-500 mx-1 flex-shrink-0" />
            )}
          </div>
        );
      })}
    </div>
  );
}

export default function AttackChainView({ attackChain }: AttackChainViewProps) {
  const steps = useMemo(() => parseAttackChain(attackChain), [attackChain]);
  
  if (steps.length === 0) {
    return (
      <div className="bg-slate-700/50 p-4 rounded border-l-4 border-rose-500">
        <p className="text-slate-200 font-mono text-sm whitespace-pre-wrap">{attackChain}</p>
      </div>
    );
  }
  
  return (
    <div className="space-y-6">
      {/* Horizontal compact view */}
      <div className="bg-slate-900/50 p-4 rounded-lg border border-slate-700">
        <div className="flex items-center gap-2 mb-3">
          <AlertTriangle className="w-4 h-4 text-rose-400" />
          <span className="text-sm text-slate-400">Attack Flow ({steps.length} steps)</span>
        </div>
        <HorizontalFlow steps={steps} />
      </div>
      
      {/* Vertical detailed view */}
      <div className="bg-slate-900/50 p-4 rounded-lg border border-slate-700">
        <div className="flex items-center gap-2 mb-4">
          <Link2 className="w-4 h-4 text-emerald-400" />
          <span className="text-sm text-slate-400">Detailed Execution Path</span>
        </div>
        <div className="pl-2">
          {steps.map((step, idx) => (
            <StepCard key={idx} step={step} index={idx} isLast={idx === steps.length - 1} />
          ))}
        </div>
      </div>
      
      {/* Legend */}
      <div className="flex flex-wrap gap-3 text-xs">
        {Object.entries(categoryConfig).map(([key, config]) => (
          <div key={key} className="flex items-center gap-1.5">
            <span className={config.color}>{config.icon}</span>
            <span className="text-slate-400 capitalize">{key}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
