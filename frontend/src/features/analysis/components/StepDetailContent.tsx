import { memo } from 'react';
import type { AnalysisResult } from '../../../shared/types';
import DynamicAnalysisView from './DynamicAnalysisView';
import {
  HashView,
  StringsView,
  FileTypeView,
  CapaView,
  YaraView,
  ThreatIntelView,
  GhidraView,
  ReportView,
} from './StepViews';

interface StepDetailContentProps {
  stepId: string;
  result: AnalysisResult;
}

const MISSING_DATA_MESSAGES: Record<string, string> = {
  file_type: 'File type identification was not performed',
  capa: 'Capability analysis was not performed',
  dynamic: 'Dynamic analysis was not performed',
  ghidra: 'Ghidra analysis was not performed',
};

export const StepDetailContent = memo(function StepDetailContent({
  stepId,
  result,
}: StepDetailContentProps) {
  const getStepData = (): unknown => {
    switch (stepId) {
      case 'hash':
        return result.hashes;
      case 'strings':
        return result.strings;
      case 'file_type':
        return result.file_type;
      case 'capa':
        return result.capa;
      case 'yara':
        return result.yara;
      case 'threat_intel':
        return result.threat_intel;
      case 'dynamic':
        return result.dynamic_analysis;
      case 'ghidra':
        return result.ghidra_analysis;
      case 'report':
        return result.malware_report;
      default:
        return null;
    }
  };

  const data = getStepData();

  if (!data) {
    const message = MISSING_DATA_MESSAGES[stepId] || 'No data available';
    return (
      <div className="mt-3 pt-3 border-t border-slate-700/50">
        <div className="text-slate-500 text-sm py-4 text-center">{message}</div>
      </div>
    );
  }

  const renderContent = () => {
    switch (stepId) {
      case 'hash':
        return <HashView data={data as Parameters<typeof HashView>[0]['data']} />;
      
      case 'strings':
        return <StringsView data={data as Parameters<typeof StringsView>[0]['data']} />;
      
      case 'file_type':
        return <FileTypeView data={data as Parameters<typeof FileTypeView>[0]['data']} />;
      
      case 'capa':
        return <CapaView data={data as Parameters<typeof CapaView>[0]['data']} />;
      
      case 'yara':
        return <YaraView data={data as Parameters<typeof YaraView>[0]['data']} />;
      
      case 'threat_intel':
        return <ThreatIntelView data={data as Parameters<typeof ThreatIntelView>[0]['data']} />;
      
      case 'dynamic': {
        const dynData = data as Record<string, unknown>;
        
        if (dynData.error) {
          return (
            <div className="bg-yellow-900/20 rounded-lg p-4 border border-yellow-800/50">
              <p className="text-yellow-400 text-sm font-medium">⚠️ {String(dynData.error)}</p>
              {typeof dynData.help === 'string' && dynData.help && (
                <p className="text-slate-400 text-xs mt-2">{dynData.help}</p>
              )}
            </div>
          );
        }
        
        if (!dynData.success && (!dynData.syscalls || (Array.isArray(dynData.syscalls) && dynData.syscalls.length === 0))) {
          return (
            <div className="bg-slate-900/50 rounded-lg p-4">
              <p className="text-slate-400 text-sm">Dynamic analysis was not performed or produced no results.</p>
            </div>
          );
        }
        
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        return <DynamicAnalysisView data={dynData as any} />;
      }
      
      case 'ghidra':
        return <GhidraView data={data as Parameters<typeof GhidraView>[0]['data']} />;
      
      case 'report':
        return <ReportView data={data as Parameters<typeof ReportView>[0]['data']} />;
      
      default:
        return (
          <div className="bg-slate-900/50 rounded-lg p-3">
            <pre className="text-xs font-mono text-slate-300 whitespace-pre-wrap">
              {JSON.stringify(data, null, 2)}
            </pre>
          </div>
        );
    }
  };

  return (
    <div className="mt-3 pt-3 border-t border-slate-700/50">
      {renderContent()}
    </div>
  );
});

export default StepDetailContent;
