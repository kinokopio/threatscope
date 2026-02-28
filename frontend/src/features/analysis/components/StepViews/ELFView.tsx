import { Cpu, FileCode, Package, Layers } from 'lucide-react';

interface ELFViewProps {
  data: {
    format?: string;
    arch?: string;
    bits?: number;
    endian?: string;
    type?: string;
    entry_point?: string;
    imports?: string[];
    sections?: Array<{ name: string; size: number; type: string }>;
    error?: string;
  };
}

export function ELFView({ data }: ELFViewProps) {
  if (data.error) {
    return (
      <div className="bg-yellow-900/20 rounded-lg p-4 border border-yellow-800/50">
        <p className="text-yellow-400 text-sm">⚠️ {data.error}</p>
      </div>
    );
  }

  const infoItems = [
    { label: 'Format', value: data.format, icon: FileCode, color: 'text-blue-400' },
    { label: 'Architecture', value: data.arch, icon: Cpu, color: 'text-purple-400' },
    { label: 'Bits', value: data.bits ? `${data.bits}-bit` : undefined, icon: Layers, color: 'text-emerald-400' },
    { label: 'Type', value: data.type, icon: Package, color: 'text-orange-400' },
  ].filter(item => item.value);

  return (
    <div className="space-y-4">
      {/* Basic Info Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {infoItems.map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="bg-slate-900/50 rounded-lg p-3">
            <div className="flex items-center gap-2 mb-1">
              <Icon className={`w-4 h-4 ${color}`} />
              <span className="text-xs text-slate-500">{label}</span>
            </div>
            <p className="text-sm text-slate-200 font-medium">{value}</p>
          </div>
        ))}
      </div>

      {/* Entry Point */}
      {data.entry_point && (
        <div className="bg-slate-900/50 rounded-lg p-3">
          <span className="text-xs text-slate-500">Entry Point</span>
          <p className="text-sm text-cyan-400 font-mono mt-1">{data.entry_point}</p>
        </div>
      )}

      {/* Imports */}
      {data.imports && data.imports.length > 0 && (
        <div className="bg-slate-900/50 rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <span className="text-sm font-medium text-slate-300">Imported Functions</span>
            <span className="text-xs text-slate-500 bg-slate-800 px-2 py-0.5 rounded-full">
              {data.imports.length}
            </span>
          </div>
          <div className="flex flex-wrap gap-2 max-h-40 overflow-y-auto">
            {data.imports.slice(0, 50).map((imp, i) => (
              <span 
                key={i} 
                className="text-xs font-mono bg-slate-800 text-slate-300 px-2 py-1 rounded"
              >
                {imp}
              </span>
            ))}
            {data.imports.length > 50 && (
              <span className="text-xs text-slate-500 px-2 py-1">
                +{data.imports.length - 50} more
              </span>
            )}
          </div>
        </div>
      )}

      {/* Sections */}
      {data.sections && data.sections.length > 0 && (
        <div className="bg-slate-900/50 rounded-lg p-4">
          <span className="text-sm font-medium text-slate-300 mb-3 block">Sections</span>
          <div className="space-y-2">
            {data.sections.map((section, i) => (
              <div key={i} className="flex items-center justify-between text-sm bg-slate-800/50 px-3 py-2 rounded">
                <span className="text-purple-400 font-mono">{section.name}</span>
                <span className="text-slate-400">{formatBytes(section.size)}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}
