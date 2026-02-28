import { Copy, Check } from 'lucide-react';
import { useState } from 'react';

interface HashViewProps {
  data: {
    md5?: string;
    sha1?: string;
    sha256?: string;
    ssdeep?: string;
  };
}

export function HashView({ data }: HashViewProps) {
  const [copied, setCopied] = useState<string | null>(null);

  const copyToClipboard = (value: string, type: string) => {
    navigator.clipboard.writeText(value);
    setCopied(type);
    setTimeout(() => setCopied(null), 2000);
  };

  const hashes = [
    { label: 'MD5', value: data.md5, color: 'text-blue-400' },
    { label: 'SHA1', value: data.sha1, color: 'text-purple-400' },
    { label: 'SHA256', value: data.sha256, color: 'text-emerald-400' },
    { label: 'SSDEEP', value: data.ssdeep, color: 'text-orange-400' },
  ].filter(h => h.value);

  return (
    <div className="space-y-3">
      {hashes.map(({ label, value, color }) => (
        <div key={label} className="bg-slate-900/50 rounded-lg p-3">
          <div className="flex items-center justify-between mb-1">
            <span className={`text-xs font-medium ${color}`}>{label}</span>
            <button
              onClick={() => copyToClipboard(value!, label)}
              className="text-slate-500 hover:text-slate-300 transition-colors"
            >
              {copied === label ? (
                <Check className="w-4 h-4 text-emerald-400" />
              ) : (
                <Copy className="w-4 h-4" />
              )}
            </button>
          </div>
          <code className="text-sm text-slate-300 font-mono break-all">{value}</code>
        </div>
      ))}
    </div>
  );
}
