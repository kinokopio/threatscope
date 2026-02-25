import { useState } from 'react';
import ReactMarkdown from 'react-markdown';
import { 
  Shield, 
  FileText, 
  AlertTriangle, 
  Target, 
  Globe, 
  ChevronRight,
  CheckCircle,
  XCircle,
  Info
} from 'lucide-react';
import type { AnalysisResult, MitreMapping } from '../types';

interface ReportViewProps {
  result: AnalysisResult;
  fileName?: string;
}

// Helper functions
const normalizeList = <T,>(items: T[] | undefined | null): T[] => 
  Array.isArray(items) ? items.filter(Boolean) : [];

const getRiskBadgeClass = (verdict: string): string => {
  if (verdict === 'malicious') return 'bg-red-900 text-red-100';
  if (verdict === 'suspicious') return 'bg-orange-700 text-orange-100';
  if (verdict === 'benign') return 'bg-green-900 text-green-100';
  return 'bg-slate-700 text-slate-200';
};

const getConfidenceColor = (confidence: number): string => {
  if (confidence >= 0.8) return 'text-red-400';
  if (confidence >= 0.5) return 'text-orange-400';
  return 'text-green-400';
};

export default function ReportView({ result, fileName }: ReportViewProps) {
  const [mitreOpen, setMitreOpen] = useState(false);
  const [iocsOpen, setIocsOpen] = useState(false);
  const [stringsOpen, setStringsOpen] = useState(false);
  const [functionsOpen, setFunctionsOpen] = useState(false);

  const { metadata, static_analysis, malware_report, ghidra_analysis } = result;

  const renderChevronButton = (
    open: boolean, 
    onClick: () => void, 
    label: string
  ) => (
    <button
      onClick={onClick}
      aria-expanded={open}
      aria-label={label}
      className="text-slate-200 bg-slate-800/60 hover:bg-slate-800 px-2 py-1 rounded flex items-center justify-center transition-colors"
    >
      <ChevronRight 
        className={`w-4 h-4 transform transition-transform ${open ? 'rotate-90' : ''}`}
      />
    </button>
  );

  const renderIocGroup = (title: string, items: string[] | undefined) => {
    const safeItems = normalizeList(items);
    if (safeItems.length === 0) return null;
    
    return (
      <div className="bg-slate-800 p-3 rounded border border-slate-700">
        <div className="flex items-center justify-between mb-2">
          <div className="text-sm font-bold text-slate-100">{title}</div>
          <div className="text-xs text-slate-400">{safeItems.length}</div>
        </div>
        <div className="flex flex-wrap gap-2">
          {safeItems.map((v, idx) => (
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
  };

  return (
    <div className="space-y-4 text-left">
      {/* 1. File Basic Info */}
      <div className="bg-slate-800 p-6 rounded-lg shadow-lg border border-slate-700">
        <h2 className="text-2xl font-bold mb-4 text-emerald-400 flex items-center">
          <FileText className="w-6 h-6 mr-2" />
          File Basic Info
        </h2>
        
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 text-sm">
          <div className="bg-slate-700 p-3 rounded col-span-2">
            <span className="block text-slate-400 text-xs">Filename</span>
            <span className="font-mono text-emerald-300 break-all">
              {fileName || metadata?.file_name || 'Unknown'}
            </span>
          </div>
          
          {static_analysis?.elf && (
            <>
              <div className="bg-slate-700 p-3 rounded">
                <span className="block text-slate-400 text-xs">Format</span>
                <span className="font-mono text-cyan-300">{static_analysis.elf.format || 'N/A'}</span>
              </div>
              <div className="bg-slate-700 p-3 rounded">
                <span className="block text-slate-400 text-xs">Architecture</span>
                <span className="font-mono text-purple-300">{static_analysis.elf.arch || 'N/A'}</span>
              </div>
              <div className="bg-slate-700 p-3 rounded">
                <span className="block text-slate-400 text-xs">Entry Point</span>
                <span className="font-mono text-yellow-300">{static_analysis.elf.entry_point || 'N/A'}</span>
              </div>
            </>
          )}
          
          <div className="bg-slate-700 p-3 rounded col-span-2 lg:col-span-4">
            <span className="block text-slate-400 text-xs">SHA256</span>
            <span className="font-mono text-slate-200 break-all text-[10px] sm:text-xs">
              {metadata?.hashes?.sha256 || static_analysis?.hashes?.sha256 || 'N/A'}
            </span>
          </div>
          
          <div className="bg-slate-700 p-3 rounded col-span-2">
            <span className="block text-slate-400 text-xs">MD5</span>
            <span className="font-mono text-slate-200 break-all text-xs">
              {metadata?.hashes?.md5 || static_analysis?.hashes?.md5 || 'N/A'}
            </span>
          </div>
        </div>
      </div>

      {/* 2. Analysis Summary (Malware Report) */}
      {malware_report && (
        <div className="bg-slate-800 p-6 rounded-lg shadow-lg border border-slate-700">
          <h2 className="text-2xl font-bold mb-4 text-emerald-400 flex items-center">
            <Shield className="w-6 h-6 mr-2" />
            Analysis Summary
          </h2>
          
          <div className="space-y-4">
            {/* Verdict and Confidence */}
            <div className="flex flex-wrap gap-4 mb-4">
              <span className={`px-4 py-2 rounded text-sm font-bold uppercase flex items-center ${getRiskBadgeClass(malware_report.verdict)}`}>
                {malware_report.verdict === 'malicious' && <XCircle className="w-4 h-4 mr-2" />}
                {malware_report.verdict === 'suspicious' && <AlertTriangle className="w-4 h-4 mr-2" />}
                {malware_report.verdict === 'benign' && <CheckCircle className="w-4 h-4 mr-2" />}
                {malware_report.verdict}
              </span>
              <span className="px-4 py-2 rounded text-sm font-bold bg-slate-700 text-slate-200">
                Confidence: <span className={getConfidenceColor(malware_report.confidence)}>
                  {(malware_report.confidence * 100).toFixed(0)}%
                </span>
              </span>
              {malware_report.family && (
                <span className="px-4 py-2 rounded text-sm font-bold bg-slate-700 text-cyan-300">
                  Family: {malware_report.family}
                </span>
              )}
            </div>

            {/* Summary */}
            <div className="bg-slate-700/50 p-4 rounded border-l-4 border-cyan-500">
              <h3 className="font-bold text-lg text-white mb-2 flex items-center">
                <Info className="w-5 h-5 mr-2" />
                Summary
              </h3>
              <div className="prose prose-invert prose-sm max-w-none">
                <ReactMarkdown>{malware_report.summary}</ReactMarkdown>
              </div>
            </div>

            {/* Capabilities */}
            {malware_report.capabilities && malware_report.capabilities.length > 0 && (
              <div className="bg-slate-700/50 p-4 rounded border-l-4 border-purple-500">
                <h3 className="font-bold text-lg text-white mb-2">Capabilities</h3>
                <div className="flex flex-wrap gap-2">
                  {malware_report.capabilities.map((cap, idx) => (
                    <span 
                      key={idx} 
                      className="px-3 py-1 rounded text-sm bg-purple-900/50 text-purple-200 border border-purple-700"
                    >
                      {cap}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Technical Details */}
            {malware_report.technical_details && (
              <div className="bg-slate-700/50 p-4 rounded border-l-4 border-blue-500">
                <h3 className="font-bold text-lg text-white mb-2">Technical Details</h3>
                <div className="grid grid-cols-2 gap-3 text-sm">
                  {Object.entries(malware_report.technical_details).map(([key, value]) => (
                    value && (
                      <div key={key} className="bg-slate-800 p-2 rounded">
                        <span className="block text-slate-400 text-xs capitalize">
                          {key.replace(/_/g, ' ')}
                        </span>
                        <span className="font-mono text-slate-200">{value}</span>
                      </div>
                    )
                  ))}
                </div>
              </div>
            )}

            {/* Recommendations */}
            {malware_report.recommendations && malware_report.recommendations.length > 0 && (
              <div className="bg-slate-700/50 p-4 rounded border-l-4 border-yellow-500">
                <h3 className="font-bold text-lg text-white mb-2">Recommendations</h3>
                <ul className="list-disc list-inside space-y-1 text-slate-300">
                  {malware_report.recommendations.map((rec, idx) => (
                    <li key={idx}>{rec}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      )}

      {/* 3. MITRE ATT&CK Mapping */}
      {malware_report?.mitre_mapping && malware_report.mitre_mapping.length > 0 && (
        <div className="bg-slate-800 p-6 rounded-lg shadow-lg border border-slate-700">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-2xl font-bold text-emerald-400 flex items-center">
              <Target className="w-6 h-6 mr-2" />
              MITRE ATT&CK Mapping
              <span className="ml-2 text-sm text-slate-400 bg-slate-700 px-2 py-0.5 rounded">
                {malware_report.mitre_mapping.length}
              </span>
            </h2>
            {renderChevronButton(mitreOpen, () => setMitreOpen(!mitreOpen), 'Toggle MITRE mapping')}
          </div>

          {mitreOpen && (
            <div className="space-y-3">
              {malware_report.mitre_mapping.map((mapping: MitreMapping, idx: number) => (
                <div key={idx} className="bg-slate-700/50 p-4 rounded border border-slate-600">
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div>
                      <span className="font-mono text-cyan-300">{mapping.technique_id}</span>
                      <span className="text-slate-200 ml-2">{mapping.technique_name}</span>
                    </div>
                    <span className="px-2 py-0.5 rounded text-xs font-semibold bg-slate-600 text-slate-200">
                      {mapping.tactic}
                    </span>
                  </div>
                  {mapping.evidence && (
                    <p className="text-slate-400 text-sm mt-2">{mapping.evidence}</p>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* 4. Extracted IOCs */}
      {malware_report?.iocs && (
        <div className="bg-slate-800 p-6 rounded-lg shadow-lg border border-slate-700">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-2xl font-bold text-emerald-400 flex items-center">
              <Globe className="w-6 h-6 mr-2" />
              Extracted IOCs
            </h2>
            {renderChevronButton(iocsOpen, () => setIocsOpen(!iocsOpen), 'Toggle IOCs')}
          </div>

          {iocsOpen && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
              {renderIocGroup('Domains', malware_report.iocs.domains)}
              {renderIocGroup('IPs', malware_report.iocs.ips)}
              {renderIocGroup('URLs', malware_report.iocs.urls)}
              {renderIocGroup('File Hashes', malware_report.iocs.file_hashes)}
              
              {!malware_report.iocs.domains?.length && 
               !malware_report.iocs.ips?.length && 
               !malware_report.iocs.urls?.length && 
               !malware_report.iocs.file_hashes?.length && (
                <div className="lg:col-span-2 text-slate-400 text-sm italic">
                  No IOCs extracted.
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* 5. Suspicious Strings */}
      {static_analysis?.strings && (
        <div className="bg-slate-800 p-6 rounded-lg shadow-lg border border-slate-700">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-2xl font-bold text-emerald-400 flex items-center">
              <AlertTriangle className="w-6 h-6 mr-2" />
              Extracted Strings
            </h2>
            {renderChevronButton(stringsOpen, () => setStringsOpen(!stringsOpen), 'Toggle strings')}
          </div>

          {stringsOpen && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
              {renderIocGroup('URLs', static_analysis.strings.urls)}
              {renderIocGroup('IPs', static_analysis.strings.ips)}
              {renderIocGroup('Domains', static_analysis.strings.domains)}
              {renderIocGroup('Suspicious', static_analysis.strings.suspicious)}
            </div>
          )}
        </div>
      )}

      {/* 6. Ghidra Analysis */}
      {ghidra_analysis?.ai_analysis && (
        <div className="bg-slate-800 p-6 rounded-lg shadow-lg border border-slate-700">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-2xl font-bold text-emerald-400 flex items-center">
              <Shield className="w-6 h-6 mr-2" />
              Ghidra Deep Analysis
              {ghidra_analysis.ai_analysis.analyzed_functions && (
                <span className="ml-2 text-sm text-slate-400 bg-slate-700 px-2 py-0.5 rounded">
                  {ghidra_analysis.ai_analysis.analyzed_functions.length} functions
                </span>
              )}
            </h2>
            {renderChevronButton(functionsOpen, () => setFunctionsOpen(!functionsOpen), 'Toggle functions')}
          </div>

          {/* Key Findings */}
          {ghidra_analysis.ai_analysis.key_findings && ghidra_analysis.ai_analysis.key_findings.length > 0 && (
            <div className="bg-slate-700/50 p-4 rounded border-l-4 border-rose-500 mb-4">
              <h3 className="font-bold text-lg text-white mb-2">Key Findings</h3>
              <ul className="list-disc list-inside space-y-1 text-slate-300">
                {ghidra_analysis.ai_analysis.key_findings.map((finding, idx) => (
                  <li key={idx}>{finding}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Analyzed Functions */}
          {functionsOpen && ghidra_analysis.ai_analysis.analyzed_functions && (
            <div className="space-y-3">
              {ghidra_analysis.ai_analysis.analyzed_functions.map((func, idx) => (
                <div key={idx} className="bg-slate-700/50 p-4 rounded border border-slate-600">
                  <div className="flex items-start justify-between">
                    <div>
                      <span className="font-mono text-cyan-300">{func.name}</span>
                      <span className="text-slate-500 text-sm ml-2">@ {func.address}</span>
                    </div>
                    {func.behavior?.risk_level && (
                      <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${
                        func.behavior.risk_level === 'high' || func.behavior.risk_level === 'critical'
                          ? 'bg-red-900 text-red-100'
                          : func.behavior.risk_level === 'medium'
                          ? 'bg-orange-800 text-orange-100'
                          : 'bg-slate-600 text-slate-200'
                      }`}>
                        {func.behavior.risk_level}
                      </span>
                    )}
                  </div>
                  {func.summary && (
                    <p className="text-slate-300 text-sm mt-2">{func.summary}</p>
                  )}
                  {func.behavior?.actions && func.behavior.actions.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-2">
                      {func.behavior.actions.map((action, aidx) => (
                        <span 
                          key={aidx} 
                          className="px-2 py-0.5 rounded text-xs bg-slate-600 text-slate-200"
                        >
                          {action}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* 7. YARA Matches */}
      {static_analysis?.yara?.matches && static_analysis.yara.matches.length > 0 && (
        <div className="bg-slate-800 p-6 rounded-lg shadow-lg border border-slate-700">
          <h2 className="text-2xl font-bold mb-4 text-emerald-400 flex items-center">
            <AlertTriangle className="w-6 h-6 mr-2" />
            YARA Matches
          </h2>
          <div className="flex flex-wrap gap-2">
            {static_analysis.yara.matches.map((match, idx) => (
              <span 
                key={idx} 
                className="px-3 py-1 rounded text-sm bg-red-900/50 text-red-200 border border-red-700"
              >
                {match}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
