import { memo, useState } from 'react';
import { Globe, ChevronRight } from 'lucide-react';
import { normalizeList } from '../../../shared/utils';

interface IocSectionProps {
  iocs: {
    domains?: string[];
    ips?: string[];
    urls?: string[];
    file_hashes?: string[];
  };
}

interface IocGroupProps {
  title: string;
  items: string[];
}

const IocGroup = memo(function IocGroup({ title, items }: IocGroupProps) {
  if (items.length === 0) return null;

  return (
    <div className="bg-slate-800 p-3 rounded border border-slate-700">
      <div className="flex items-center justify-between mb-2">
        <div className="text-sm font-bold text-slate-100">{title}</div>
        <div className="text-xs text-slate-400">{items.length}</div>
      </div>
      <div className="flex flex-wrap gap-2">
        {items.map((v, idx) => (
          <span
            key={`${title}-${idx}`}
            className="font-mono text-[11px] px-2 py-1 rounded bg-slate-700/60 text-slate-100 break-all"
          >
            {v}
          </span>
        ))}
      </div>
    </div>
  );
});

export const IocSection = memo(function IocSection({ iocs }: IocSectionProps) {
  const [isOpen, setIsOpen] = useState(false);

  const domains = normalizeList(iocs.domains);
  const ips = normalizeList(iocs.ips);
  const urls = normalizeList(iocs.urls);
  const fileHashes = normalizeList(iocs.file_hashes);

  const hasAnyIocs = domains.length > 0 || ips.length > 0 || urls.length > 0 || fileHashes.length > 0;

  if (!hasAnyIocs) return null;

  return (
    <div className="bg-slate-800 p-6 rounded-lg shadow-lg border border-slate-700">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-2xl font-bold text-emerald-400 flex items-center">
          <Globe className="w-6 h-6 mr-2" />
          Extracted IOCs
        </h2>
        <button
          onClick={() => setIsOpen(!isOpen)}
          aria-expanded={isOpen}
          className="text-slate-200 bg-slate-800/60 hover:bg-slate-800 px-2 py-1 rounded flex items-center justify-center transition-colors"
        >
          <ChevronRight
            className={`w-4 h-4 transform transition-transform ${isOpen ? 'rotate-90' : ''}`}
          />
        </button>
      </div>

      {isOpen && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          <IocGroup title="Domains" items={domains} />
          <IocGroup title="IPs" items={ips} />
          <IocGroup title="URLs" items={urls} />
          <IocGroup title="File Hashes" items={fileHashes} />
        </div>
      )}
    </div>
  );
});

export default IocSection;
