import { memo } from 'react';
import { FileText } from 'lucide-react';

interface FileInfoSectionProps {
  fileName?: string;
  format?: string;
  arch?: string;
  entryPoint?: string;
  sha256?: string;
  md5?: string;
}

export const FileInfoSection = memo(function FileInfoSection({
  fileName,
  format,
  arch,
  entryPoint,
  sha256,
  md5,
}: FileInfoSectionProps) {
  return (
    <div className="bg-slate-800 p-6 rounded-lg shadow-lg border border-slate-700">
      <h2 className="text-2xl font-bold mb-4 text-emerald-400 flex items-center">
        <FileText className="w-6 h-6 mr-2" />
        File Basic Info
      </h2>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 text-sm">
        <div className="bg-slate-700 p-3 rounded col-span-2">
          <span className="block text-slate-400 text-xs">Filename</span>
          <span className="font-mono text-emerald-300 break-all">
            {fileName || 'Unknown'}
          </span>
        </div>

        {format && (
          <div className="bg-slate-700 p-3 rounded">
            <span className="block text-slate-400 text-xs">Format</span>
            <span className="font-mono text-cyan-300">{format}</span>
          </div>
        )}

        {arch && (
          <div className="bg-slate-700 p-3 rounded">
            <span className="block text-slate-400 text-xs">Architecture</span>
            <span className="font-mono text-purple-300">{arch}</span>
          </div>
        )}

        {entryPoint && (
          <div className="bg-slate-700 p-3 rounded">
            <span className="block text-slate-400 text-xs">Entry Point</span>
            <span className="font-mono text-yellow-300">{entryPoint}</span>
          </div>
        )}

        {sha256 && (
          <div className="bg-slate-700 p-3 rounded col-span-2 lg:col-span-4">
            <span className="block text-slate-400 text-xs">SHA256</span>
            <span className="font-mono text-slate-200 break-all text-[10px] sm:text-xs">
              {sha256}
            </span>
          </div>
        )}

        {md5 && (
          <div className="bg-slate-700 p-3 rounded col-span-2">
            <span className="block text-slate-400 text-xs">MD5</span>
            <span className="font-mono text-slate-200 break-all text-xs">{md5}</span>
          </div>
        )}
      </div>
    </div>
  );
});

export default FileInfoSection;
