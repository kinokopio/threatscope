import { useMemo } from 'react';
import { ChevronRight } from 'lucide-react';

interface AttackStep {
  name: string;
  address?: string;
  description?: string;
}

interface AttackChainViewProps {
  attackChain: string;
}

function parseAttackChain(chainText: string): AttackStep[] {
  const steps: AttackStep[] = [];
  
  // Split by → or ->
  const parts = chainText.split(/\s*(?:→|->)\s*/);
  
  for (const part of parts) {
    if (!part.trim()) continue;
    
    // Pattern 1: "func_name (0x00123456) description" or "func_name (0x00123456)"
    const addressMatch = part.match(/^([^\(]+)\s*\(0x([0-9a-fA-F]+)\)\s*(.*)/);
    if (addressMatch) {
      const [, name, address, description] = addressMatch;
      steps.push({
        name: name.trim(),
        address: `0x${address}`,
        description: description.trim() || undefined,
      });
      continue;
    }
    
    // Pattern 2: "func_name (description)" - description in parentheses
    const descMatch = part.match(/^([^\(]+)\s*\(([^)]+)\)\s*$/);
    if (descMatch) {
      const [, name, description] = descMatch;
      steps.push({
        name: name.trim(),
        description: description.trim(),
      });
      continue;
    }
    
    // Pattern 3: Just function name
    steps.push({
      name: part.trim(),
    });
  }
  
  return steps;
}

function StepNode({ step, index }: { step: AttackStep; index: number }) {
  return (
    <div className="flex flex-col items-center">
      {/* Step number */}
      <div className="text-[10px] text-slate-500 mb-1">Step {index + 1}</div>
      
      {/* Node box */}
      <div className="bg-slate-800 border border-slate-600 rounded px-3 py-2 text-center hover:border-slate-500 transition-colors whitespace-nowrap">
        {/* Function name */}
        <div className="font-mono text-sm text-slate-200">
          {step.name}
        </div>
        
        {/* Address if present */}
        {step.address && (
          <div className="text-[10px] font-mono text-slate-500 mt-0.5">
            {step.address}
          </div>
        )}
        
        {/* Description if present */}
        {step.description && (
          <div className="text-xs text-slate-400 mt-1">
            {step.description}
          </div>
        )}
      </div>
    </div>
  );
}

function Arrow() {
  return (
    <div className="flex items-center justify-center px-1 text-slate-500">
      <ChevronRight className="w-5 h-5" />
    </div>
  );
}

export default function AttackChainView({ attackChain }: AttackChainViewProps) {
  const steps = useMemo(() => parseAttackChain(attackChain), [attackChain]);
  
  // If parsing failed, show raw text
  if (steps.length === 0) {
    return (
      <div className="bg-slate-800/50 p-4 rounded border border-slate-700">
        <pre className="text-sm text-slate-300 whitespace-pre-wrap font-mono">{attackChain}</pre>
      </div>
    );
  }
  
  return (
    <div className="bg-slate-800/30 p-4 rounded border border-slate-700">
      {/* Horizontal scrollable flow */}
      <div className="overflow-x-auto">
        <div className="flex items-center gap-1 pb-2 min-w-max">
          {steps.map((step, idx) => (
            <div key={idx} className="flex items-center">
              <StepNode step={step} index={idx} />
              {idx < steps.length - 1 && <Arrow />}
            </div>
          ))}
        </div>
      </div>
      
      {/* Step count */}
      <div className="text-xs text-slate-500 mt-2 pt-2 border-t border-slate-700/50">
        {steps.length} steps in attack chain
      </div>
    </div>
  );
}
