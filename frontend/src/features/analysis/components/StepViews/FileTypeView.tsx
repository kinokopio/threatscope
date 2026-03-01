import { FileType, Cpu, Package, Shield, Wrench, Library } from 'lucide-react';
import type { FileTypeResult } from '../../../../shared/types';

interface FileTypeViewProps {
  data: FileTypeResult;
}

export function FileTypeView({ data }: FileTypeViewProps) {
  if (data.error) {
    return (
      <div className="bg-yellow-900/20 rounded-lg p-4 border border-yellow-800/50">
        <p className="text-yellow-400 text-sm">⚠️ {data.error}</p>
      </div>
    );
  }

  const infoItems = [
    { label: 'Format', value: data.format, icon: FileType, color: 'text-blue-400' },
    { label: 'Architecture', value: data.arch, icon: Cpu, color: 'text-purple-400' },
    { label: 'Category', value: data.category, icon: Package, color: 'text-emerald-400' },
    { label: 'Platform', value: data.platform, icon: Shield, color: 'text-orange-400' },
  ].filter(item => item.value);

  const hasPackers = data.packers && data.packers.length > 0;
  const hasCompilers = data.compilers && data.compilers.length > 0;
  const hasProtectors = data.protectors && data.protectors.length > 0;
  const hasLibraries = data.libraries && data.libraries.length > 0;

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

      {/* Script Language */}
      {data.script_language && (
        <div className="bg-slate-900/50 rounded-lg p-3">
          <span className="text-xs text-slate-500">Script Language</span>
          <p className="text-sm text-cyan-400 font-mono mt-1">{data.script_language}</p>
        </div>
      )}

      {/* Packers */}
      {hasPackers && (
        <div className="bg-red-900/20 rounded-lg p-4 border border-red-800/50">
          <div className="flex items-center gap-2 mb-3">
            <Package className="w-4 h-4 text-red-400" />
            <span className="text-sm font-medium text-red-400">Packers Detected</span>
            <span className="text-xs text-slate-500 bg-slate-800 px-2 py-0.5 rounded-full">
              {data.packers!.length}
            </span>
          </div>
          <div className="flex flex-wrap gap-2">
            {data.packers!.map((packer, i) => (
              <span 
                key={i} 
                className="text-xs font-mono bg-red-900/30 text-red-300 px-2 py-1 rounded border border-red-800/50"
              >
                {packer.name}{packer.version ? ` v${packer.version}` : ''}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Protectors */}
      {hasProtectors && (
        <div className="bg-orange-900/20 rounded-lg p-4 border border-orange-800/50">
          <div className="flex items-center gap-2 mb-3">
            <Shield className="w-4 h-4 text-orange-400" />
            <span className="text-sm font-medium text-orange-400">Protectors Detected</span>
            <span className="text-xs text-slate-500 bg-slate-800 px-2 py-0.5 rounded-full">
              {data.protectors!.length}
            </span>
          </div>
          <div className="flex flex-wrap gap-2">
            {data.protectors!.map((protector, i) => (
              <span 
                key={i} 
                className="text-xs font-mono bg-orange-900/30 text-orange-300 px-2 py-1 rounded border border-orange-800/50"
              >
                {protector.name}{protector.version ? ` v${protector.version}` : ''}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Compilers */}
      {hasCompilers && (
        <div className="bg-slate-900/50 rounded-lg p-4">
          <div className="flex items-center gap-2 mb-3">
            <Wrench className="w-4 h-4 text-slate-400" />
            <span className="text-sm font-medium text-slate-300">Compilers</span>
            <span className="text-xs text-slate-500 bg-slate-800 px-2 py-0.5 rounded-full">
              {data.compilers!.length}
            </span>
          </div>
          <div className="flex flex-wrap gap-2">
            {data.compilers!.map((compiler, i) => (
              <span 
                key={i} 
                className="text-xs font-mono bg-slate-800 text-slate-300 px-2 py-1 rounded"
              >
                {compiler.name}{compiler.version ? ` v${compiler.version}` : ''}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Libraries */}
      {hasLibraries && (
        <div className="bg-slate-900/50 rounded-lg p-4">
          <div className="flex items-center gap-2 mb-3">
            <Library className="w-4 h-4 text-slate-400" />
            <span className="text-sm font-medium text-slate-300">Libraries</span>
            <span className="text-xs text-slate-500 bg-slate-800 px-2 py-0.5 rounded-full">
              {data.libraries!.length}
            </span>
          </div>
          <div className="flex flex-wrap gap-2">
            {data.libraries!.map((lib, i) => (
              <span 
                key={i} 
                className="text-xs font-mono bg-slate-800 text-slate-300 px-2 py-1 rounded"
              >
                {lib.name}{lib.version ? ` v${lib.version}` : ''}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Fallback indicator */}
      {data.is_fallback && (
        <div className="text-xs text-slate-500 text-center">
          ⚠️ Using fallback detection (diec service unavailable)
        </div>
      )}
    </div>
  );
}
