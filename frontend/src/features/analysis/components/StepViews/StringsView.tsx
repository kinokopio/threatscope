import { Globe, Server, Link2, AlertTriangle } from 'lucide-react';

interface StringsViewProps {
  data: {
    urls?: string[];
    ips?: string[];
    domains?: string[];
    suspicious?: string[];
    emails?: string[];
    paths?: string[];
  };
}

export function StringsView({ data }: StringsViewProps) {
  const sections = [
    { 
      label: 'URLs', 
      items: data.urls || [], 
      icon: Link2, 
      color: 'text-blue-400',
      bgColor: 'bg-blue-500/10',
      borderColor: 'border-blue-500/30'
    },
    { 
      label: 'IP Addresses', 
      items: data.ips || [], 
      icon: Server, 
      color: 'text-purple-400',
      bgColor: 'bg-purple-500/10',
      borderColor: 'border-purple-500/30'
    },
    { 
      label: 'Domains', 
      items: data.domains || [], 
      icon: Globe, 
      color: 'text-emerald-400',
      bgColor: 'bg-emerald-500/10',
      borderColor: 'border-emerald-500/30'
    },
    { 
      label: 'Suspicious Strings', 
      items: data.suspicious || [], 
      icon: AlertTriangle, 
      color: 'text-orange-400',
      bgColor: 'bg-orange-500/10',
      borderColor: 'border-orange-500/30'
    },
  ];

  const hasData = sections.some(s => s.items.length > 0);

  if (!hasData) {
    return (
      <div className="text-center py-6 text-slate-500">
        <p>No notable strings extracted from this binary</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {sections.map(({ label, items, icon: Icon, color, bgColor, borderColor }) => (
        items.length > 0 && (
          <div key={label} className={`${bgColor} rounded-lg border ${borderColor} p-4`}>
            <div className="flex items-center gap-2 mb-3">
              <Icon className={`w-4 h-4 ${color}`} />
              <span className={`text-sm font-medium ${color}`}>{label}</span>
              <span className="text-xs text-slate-500 bg-slate-800 px-2 py-0.5 rounded-full">
                {items.length}
              </span>
            </div>
            <div className="space-y-1 max-h-40 overflow-y-auto">
              {items.slice(0, 20).map((item, i) => (
                <div key={i} className="text-sm text-slate-300 font-mono break-all bg-slate-900/50 px-2 py-1 rounded">
                  {item}
                </div>
              ))}
              {items.length > 20 && (
                <div className="text-xs text-slate-500 pt-2">
                  ... and {items.length - 20} more
                </div>
              )}
            </div>
          </div>
        )
      ))}
    </div>
  );
}
