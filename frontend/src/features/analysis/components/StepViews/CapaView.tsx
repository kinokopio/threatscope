import { Cpu, Target, Layers, Clock, AlertTriangle } from 'lucide-react';
import type { CapaResult } from '../../../../shared/types';

interface CapaViewProps {
  data: CapaResult;
}

const TACTIC_COLORS: Record<string, string> = {
  'reconnaissance': 'bg-slate-500/20 text-slate-400 border-slate-500/30',
  'resource-development': 'bg-slate-500/20 text-slate-400 border-slate-500/30',
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

const NAMESPACE_COLORS: Record<string, string> = {
  'anti-analysis': 'text-red-400 bg-red-500/10 border-red-500/30',
  'collection': 'text-indigo-400 bg-indigo-500/10 border-indigo-500/30',
  'communication': 'text-purple-400 bg-purple-500/10 border-purple-500/30',
  'cryptography': 'text-pink-400 bg-pink-500/10 border-pink-500/30',
  'data-manipulation': 'text-orange-400 bg-orange-500/10 border-orange-500/30',
  'executable': 'text-blue-400 bg-blue-500/10 border-blue-500/30',
  'host-interaction': 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
  'impact': 'text-rose-400 bg-rose-500/10 border-rose-500/30',
  'persistence': 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
};

export function CapaView({ data }: CapaViewProps) {
  if (data.error) {
    return (
      <div className="bg-red-900/20 rounded-lg p-4 border border-red-800/50">
        <p className="text-red-400 text-sm">❌ {data.error}</p>
      </div>
    );
  }

  if (data.skipped) {
    return (
      <div className="bg-slate-900/50 rounded-lg p-4">
        <div className="flex items-center gap-2 text-slate-400">
          <AlertTriangle className="w-4 h-4" />
          <span className="text-sm">{data.reason || 'Capability analysis was skipped'}</span>
        </div>
      </div>
    );
  }

  const capabilities = data.capabilities || [];
  const attack = data.attack || {};
  const mbc = data.mbc || {};

  // Group capabilities by namespace
  const capsByNamespace = capabilities.reduce((acc, cap) => {
    const ns = cap.namespace?.split('/')[0] || 'other';
    if (!acc[ns]) acc[ns] = [];
    acc[ns].push(cap);
    return acc;
  }, {} as Record<string, typeof capabilities>);

  return (
    <div className="space-y-4">
      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="bg-slate-900/50 rounded-lg p-3">
          <div className="flex items-center gap-2 mb-1">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <span className="text-xs text-slate-500">Capabilities</span>
          </div>
          <p className="text-lg text-slate-200 font-medium">{capabilities.length}</p>
        </div>
        <div className="bg-slate-900/50 rounded-lg p-3">
          <div className="flex items-center gap-2 mb-1">
            <Target className="w-4 h-4 text-purple-400" />
            <span className="text-xs text-slate-500">ATT&CK Techniques</span>
          </div>
          <p className="text-lg text-slate-200 font-medium">{attack.techniques?.length || 0}</p>
        </div>
        <div className="bg-slate-900/50 rounded-lg p-3">
          <div className="flex items-center gap-2 mb-1">
            <Layers className="w-4 h-4 text-emerald-400" />
            <span className="text-xs text-slate-500">MBC Behaviors</span>
          </div>
          <p className="text-lg text-slate-200 font-medium">{mbc.behaviors?.length || 0}</p>
        </div>
        <div className="bg-slate-900/50 rounded-lg p-3">
          <div className="flex items-center gap-2 mb-1">
            <Clock className="w-4 h-4 text-orange-400" />
            <span className="text-xs text-slate-500">Analysis Time</span>
          </div>
          <p className="text-lg text-slate-200 font-medium">{data.analysis_time?.toFixed(1) || 0}s</p>
        </div>
      </div>

      {/* ATT&CK Techniques */}
      {attack.techniques && attack.techniques.length > 0 && (
        <div className="bg-purple-900/20 rounded-lg p-4 border border-purple-800/50">
          <div className="flex items-center gap-2 mb-3">
            <Target className="w-4 h-4 text-purple-400" />
            <span className="text-sm font-medium text-purple-400">MITRE ATT&CK Techniques</span>
          </div>
          {attack.tactics && attack.tactics.length > 0 && (
            <div className="flex flex-wrap gap-2 mb-3">
              {attack.tactics.map((tactic, i) => {
                const colorClass = TACTIC_COLORS[tactic.toLowerCase().replace(/\s+/g, '-')] || 'bg-slate-500/20 text-slate-400 border-slate-500/30';
                return (
                  <span key={i} className={`text-xs px-2 py-1 rounded border ${colorClass}`}>
                    {tactic}
                  </span>
                );
              })}
            </div>
          )}
          <div className="space-y-2 max-h-48 overflow-y-auto">
            {attack.techniques.map((tech, i) => (
              <div key={i} className="flex items-center gap-2 bg-slate-900/50 rounded px-3 py-2">
                <span className="text-xs font-mono bg-purple-900/50 text-purple-300 px-1.5 py-0.5 rounded">
                  {tech.id}
                </span>
                <span className="text-sm text-slate-200">{tech.name}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* MBC Behaviors */}
      {mbc.behaviors && mbc.behaviors.length > 0 && (
        <div className="bg-emerald-900/20 rounded-lg p-4 border border-emerald-800/50">
          <div className="flex items-center gap-2 mb-3">
            <Layers className="w-4 h-4 text-emerald-400" />
            <span className="text-sm font-medium text-emerald-400">Malware Behavior Catalog</span>
          </div>
          <div className="space-y-2 max-h-48 overflow-y-auto">
            {mbc.behaviors.map((behavior, i) => (
              <div key={i} className="flex items-center gap-2 bg-slate-900/50 rounded px-3 py-2">
                <span className="text-xs font-mono bg-emerald-900/50 text-emerald-300 px-1.5 py-0.5 rounded">
                  {behavior.id}
                </span>
                <span className="text-sm text-slate-200">{behavior.name}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Capabilities by Namespace */}
      {Object.entries(capsByNamespace).length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <span className="text-sm font-medium text-slate-300">Detected Capabilities</span>
          </div>
          {Object.entries(capsByNamespace).map(([namespace, caps]) => {
            const colorClass = NAMESPACE_COLORS[namespace] || 'text-slate-400 bg-slate-500/10 border-slate-500/30';
            return (
              <div key={namespace} className={`rounded-lg border p-4 ${colorClass}`}>
                <div className="flex items-center justify-between mb-2">
                  <span className="font-medium capitalize">{namespace.replace(/-/g, ' ')}</span>
                  <span className="text-xs bg-slate-800 px-2 py-0.5 rounded-full text-slate-400">
                    {caps.length}
                  </span>
                </div>
                <div className="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto">
                  {caps.slice(0, 20).map((cap, i) => (
                    <span 
                      key={i} 
                      className="text-xs bg-slate-900/50 text-slate-300 px-2 py-1 rounded"
                    >
                      {cap.name}
                    </span>
                  ))}
                  {caps.length > 20 && (
                    <span className="text-xs text-slate-500 px-2 py-1">
                      +{caps.length - 20} more
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Empty state */}
      {capabilities.length === 0 && (!attack.techniques || attack.techniques.length === 0) && (
        <div className="text-center py-6 text-slate-500">
          <Cpu className="w-8 h-8 mx-auto mb-2 opacity-50" />
          <p>No capabilities detected</p>
          <p className="text-xs mt-1">File may be benign or obfuscated</p>
        </div>
      )}
    </div>
  );
}
