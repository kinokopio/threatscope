import { Target, ChevronRight } from 'lucide-react';

interface MitreViewProps {
  data: {
    techniques?: Array<{
      id: string;
      name: string;
      tactic?: string;
      description?: string;
    }>;
    tactics?: string[];
  };
}

const TACTIC_COLORS: Record<string, string> = {
  'initial-access': 'bg-red-500/20 text-red-400 border-red-500/30',
  'execution': 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  'persistence': 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  'privilege-escalation': 'bg-lime-500/20 text-lime-400 border-lime-500/30',
  'defense-evasion': 'bg-green-500/20 text-green-400 border-green-500/30',
  'credential-access': 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
  'discovery': 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
  'lateral-movement': 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  'collection': 'bg-indigo-500/20 text-indigo-400 border-indigo-500/30',
  'command-and-control': 'bg-purple-500/20 text-purple-400 border-purple-500/30',
  'exfiltration': 'bg-pink-500/20 text-pink-400 border-pink-500/30',
  'impact': 'bg-rose-500/20 text-rose-400 border-rose-500/30',
};

export function MitreView({ data }: MitreViewProps) {
  const techniques = data.techniques || [];

  if (techniques.length === 0) {
    return (
      <div className="text-center py-6 text-slate-500">
        <Target className="w-8 h-8 mx-auto mb-2 opacity-50" />
        <p>No MITRE ATT&CK techniques identified</p>
      </div>
    );
  }

  // Group by tactic
  const byTactic = techniques.reduce((acc, tech) => {
    const tactic = tech.tactic || 'unknown';
    if (!acc[tactic]) acc[tactic] = [];
    acc[tactic].push(tech);
    return acc;
  }, {} as Record<string, typeof techniques>);

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2 mb-2">
        <Target className="w-5 h-5 text-purple-400" />
        <span className="text-purple-400 font-medium">{techniques.length} Technique{techniques.length > 1 ? 's' : ''} Identified</span>
      </div>

      {Object.entries(byTactic).map(([tactic, techs]) => {
        const colorClass = TACTIC_COLORS[tactic.toLowerCase().replace(/\s+/g, '-')] || 'bg-slate-500/20 text-slate-400 border-slate-500/30';
        
        return (
          <div key={tactic} className={`rounded-lg border p-4 ${colorClass}`}>
            <div className="flex items-center gap-2 mb-3">
              <ChevronRight className="w-4 h-4" />
              <span className="font-medium capitalize">{tactic.replace(/-/g, ' ')}</span>
              <span className="text-xs opacity-70">({techs.length})</span>
            </div>
            <div className="space-y-2">
              {techs.map((tech, i) => (
                <div key={i} className="bg-slate-900/50 rounded px-3 py-2">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono bg-slate-800 px-1.5 py-0.5 rounded text-cyan-400">
                      {tech.id}
                    </span>
                    <span className="text-sm text-slate-200">{tech.name}</span>
                  </div>
                  {tech.description && (
                    <p className="text-xs text-slate-400 mt-1 line-clamp-2">{tech.description}</p>
                  )}
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}
