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
  Info,
  Zap,
  Link2,
  Terminal,
  BookOpen
} from 'lucide-react';
import type { 
  UnifiedReport, 
  KeyFinding, 
  AnalyzedFunctionDetail, 
  IoCItem,
  Recommendation 
} from '../../../shared/types';

interface UnifiedReportViewProps {
  report: UnifiedReport;
  fileName?: string;
  hashes?: { md5?: string; sha256?: string };
}

const getSeverityBadgeClass = (severity: string): string => {
  const s = severity.toLowerCase();
  if (s === 'critical') return 'bg-red-900 text-red-100';
  if (s === 'high') return 'bg-orange-800 text-orange-100';
  if (s === 'medium') return 'bg-yellow-800 text-yellow-100';
  if (s === 'low') return 'bg-blue-800 text-blue-100';
  return 'bg-slate-700 text-slate-200';
};

const getPriorityBadgeClass = (priority: string): string => {
  if (priority === 'immediate') return 'bg-red-900 text-red-100';
  if (priority === 'high') return 'bg-orange-800 text-orange-100';
  if (priority === 'medium') return 'bg-yellow-800 text-yellow-100';
  return 'bg-slate-700 text-slate-200';
};

const CollapsibleSection = ({ 
  title, 
  icon, 
  count, 
  defaultOpen = false,
  children 
}: { 
  title: string; 
  icon: React.ReactNode; 
  count?: number;
  defaultOpen?: boolean;
  children: React.ReactNode;
}) => {
  const [isOpen, setIsOpen] = useState(defaultOpen);
  
  return (
    <div className="bg-slate-800 p-6 rounded-lg shadow-lg border border-slate-700">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-2xl font-bold text-emerald-400 flex items-center">
          {icon}
          <span className="ml-2">{title}</span>
          {count !== undefined && (
            <span className="ml-2 text-sm text-slate-400 bg-slate-700 px-2 py-0.5 rounded">
              {count}
            </span>
          )}
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
      {isOpen && children}
    </div>
  );
};

const FindingCard = ({ finding }: { finding: KeyFinding }) => (
  <div className="bg-slate-700/50 p-4 rounded border border-slate-600 mb-3">
    <div className="flex items-start justify-between mb-2">
      <h4 className="font-semibold text-white">{finding.title}</h4>
      <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${getSeverityBadgeClass(finding.severity)}`}>
        {finding.severity}
      </span>
    </div>
    
    <p className="text-slate-300 mb-4">{finding.description}</p>
    
    {finding.evidence.length > 0 && (
      <div className="mb-4">
        <h5 className="text-sm font-medium text-slate-400 mb-2">Evidence</h5>
        <ul className="space-y-1">
          {finding.evidence.map((e, i) => (
            <li key={i} className="font-mono text-xs text-slate-400 bg-slate-800 p-2 rounded break-all">
              {e}
            </li>
          ))}
        </ul>
      </div>
    )}
    
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
      <div>
        <span className="text-slate-400 block mb-1">Impact</span>
        <p className="text-slate-200">{finding.impact}</p>
      </div>
      <div>
        <span className="text-slate-400 block mb-1">Recommendation</span>
        <p className="text-slate-200">{finding.recommendation}</p>
      </div>
    </div>
    
    {finding.mitre_technique && (
      <div className="mt-4 pt-4 border-t border-slate-600">
        <span className="inline-flex items-center px-2 py-1 rounded text-xs bg-purple-900/50 text-purple-200">
          <Target className="w-3 h-3 mr-1" />
          {finding.mitre_technique}
        </span>
      </div>
    )}
  </div>
);

const FunctionCard = ({ func }: { func: AnalyzedFunctionDetail }) => (
  <div className="bg-slate-700/50 p-4 rounded border border-slate-600">
    <div className="flex items-start justify-between">
      <div>
        <span className="font-mono text-cyan-300">{func.name}</span>
        {func.address && func.address !== '0x0' && (
          <span className="text-slate-500 text-sm ml-2">@ {func.address}</span>
        )}
      </div>
      <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${getSeverityBadgeClass(func.risk)}`}>
        {func.risk}
      </span>
    </div>
    {func.purpose && (
      <p className="text-slate-300 text-sm mt-2">{func.purpose}</p>
    )}
    {func.analysis && (
      <p className="text-slate-400 text-xs mt-1">{func.analysis}</p>
    )}
  </div>
);

const IoCGroup = ({ title, items }: { title: string; items: IoCItem[] }) => {
  if (items.length === 0) return null;
  
  return (
    <div className="bg-slate-800 p-3 rounded border border-slate-700">
      <div className="flex items-center justify-between mb-2">
        <div className="text-sm font-bold text-slate-100">{title}</div>
        <div className="text-xs text-slate-400">{items.length}</div>
      </div>
      <div className="space-y-2">
        {items.map((item, idx) => (
          <div key={idx} className="flex items-center justify-between bg-slate-700/60 p-2 rounded">
            <span className="font-mono text-[11px] text-slate-100 break-all">{item.value}</span>
            <div className="flex items-center gap-2 ml-2 flex-shrink-0">
              {item.context && (
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-900/50 text-cyan-300">
                  {item.context}
                </span>
              )}
              <span className="text-[10px] text-slate-500">{item.source}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

const RecommendationCard = ({ rec }: { rec: Recommendation }) => (
  <div className="flex items-start gap-3 bg-slate-700/50 p-3 rounded">
    <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase flex-shrink-0 ${getPriorityBadgeClass(rec.priority)}`}>
      {rec.priority}
    </span>
    <div>
      <p className="text-slate-200">{rec.action}</p>
      {rec.details && (
        <p className="text-slate-400 text-sm mt-1">{rec.details}</p>
      )}
    </div>
  </div>
);

export default function UnifiedReportView({ report }: UnifiedReportViewProps) {
  const { 
    verdict, 
    confidence, 
    severity,
    summary,
    executive_summary,
    classification,
    key_findings,
    analyzed_functions,
    attack_chain,
    mitre_mapping,
    iocs,
    technical_details,
    recommendations,
    data_sources
  } = report;

  return (
    <div className="space-y-4 text-left">
      {/* Verdict Banner */}
      <div className={`p-6 rounded-lg border-l-4 ${
        verdict === 'malicious' ? 'bg-red-900/20 border-red-500' :
        verdict === 'suspicious' ? 'bg-orange-900/20 border-orange-500' :
        'bg-green-900/20 border-green-500'
      }`}>
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-4">
            {verdict === 'malicious' && <XCircle className="w-12 h-12 text-red-400" />}
            {verdict === 'suspicious' && <AlertTriangle className="w-12 h-12 text-orange-400" />}
            {verdict === 'benign' && <CheckCircle className="w-12 h-12 text-green-400" />}
            <div>
              <h2 className="text-2xl font-bold uppercase text-white">{verdict}</h2>
              {classification.family && (
                <p className="text-slate-400">Family: {classification.family}</p>
              )}
              <p className="text-slate-400">Type: {classification.type}</p>
            </div>
          </div>
          <div className="flex gap-4">
            <div className="bg-slate-800 px-4 py-2 rounded">
              <span className="text-slate-400 text-sm">Confidence</span>
              <p className="text-xl font-bold text-white">{(confidence * 100).toFixed(0)}%</p>
            </div>
            <div className="bg-slate-800 px-4 py-2 rounded">
              <span className="text-slate-400 text-sm">Severity</span>
              <p className={`text-xl font-bold uppercase ${getSeverityBadgeClass(severity).replace('bg-', 'text-').replace('-900', '-400').replace('-800', '-400').replace('-700', '-400')}`}>
                {severity}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Executive Summary */}
      <div className="bg-slate-800 p-6 rounded-lg shadow-lg border border-slate-700">
        <h2 className="text-2xl font-bold mb-4 text-emerald-400 flex items-center">
          <Info className="w-6 h-6 mr-2" />
          Executive Summary
        </h2>
        <p className="text-lg text-slate-200">{executive_summary}</p>
      </div>

      {/* Detailed Summary */}
      <div className="bg-slate-800 p-6 rounded-lg shadow-lg border border-slate-700">
        <h2 className="text-2xl font-bold mb-4 text-emerald-400 flex items-center">
          <BookOpen className="w-6 h-6 mr-2" />
          Analysis Summary
        </h2>
        <div className="prose prose-invert prose-sm max-w-none">
          <ReactMarkdown>{summary}</ReactMarkdown>
        </div>
      </div>

      {/* Key Findings */}
      {key_findings.length > 0 && (
        <CollapsibleSection 
          title="Key Findings" 
          icon={<Zap className="w-6 h-6" />}
          count={key_findings.length}
          defaultOpen={true}
        >
          <div className="space-y-3">
            {key_findings.map((finding) => (
              <FindingCard key={finding.id} finding={finding} />
            ))}
          </div>
        </CollapsibleSection>
      )}

      {/* Attack Chain */}
      {attack_chain && (
        <div className="bg-slate-800 p-6 rounded-lg shadow-lg border border-slate-700">
          <h2 className="text-2xl font-bold mb-4 text-emerald-400 flex items-center">
            <Link2 className="w-6 h-6 mr-2" />
            Attack Chain
          </h2>
          <div className="bg-slate-700/50 p-4 rounded border-l-4 border-rose-500">
            <p className="text-slate-200 font-mono text-sm whitespace-pre-wrap">{attack_chain}</p>
          </div>
        </div>
      )}

      {/* MITRE ATT&CK */}
      {mitre_mapping.length > 0 && (
        <CollapsibleSection 
          title="MITRE ATT&CK" 
          icon={<Target className="w-6 h-6" />}
          count={mitre_mapping.length}
        >
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {mitre_mapping.map((mapping, idx) => (
              <div key={idx} className="bg-slate-700/50 p-3 rounded border border-slate-600">
                <div className="flex items-center justify-between mb-2">
                  <span className="font-mono text-cyan-300">{mapping.technique_id}</span>
                  {mapping.tactic && (
                    <span className="px-2 py-0.5 rounded text-xs bg-slate-600 text-slate-200">
                      {mapping.tactic}
                    </span>
                  )}
                </div>
                <p className="text-slate-200 text-sm">{mapping.technique_name}</p>
                <p className="text-slate-400 text-xs mt-1">{mapping.evidence}</p>
              </div>
            ))}
          </div>
        </CollapsibleSection>
      )}

      {/* Analyzed Functions */}
      {analyzed_functions.length > 0 && (
        <CollapsibleSection 
          title="Analyzed Functions" 
          icon={<Terminal className="w-6 h-6" />}
          count={analyzed_functions.length}
        >
          <div className="space-y-3">
            {analyzed_functions.map((func, idx) => (
              <FunctionCard key={idx} func={func} />
            ))}
          </div>
        </CollapsibleSection>
      )}

      {/* IOCs */}
      <CollapsibleSection 
        title="Indicators of Compromise" 
        icon={<Globe className="w-6 h-6" />}
        count={iocs.domains.length + iocs.ips.length + iocs.urls.length + iocs.file_hashes.length}
      >
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          <IoCGroup title="Domains" items={iocs.domains} />
          <IoCGroup title="IP Addresses" items={iocs.ips} />
          <IoCGroup title="URLs" items={iocs.urls} />
          <IoCGroup title="File Hashes" items={iocs.file_hashes} />
          <IoCGroup title="File Paths" items={iocs.file_paths} />
          <IoCGroup title="Registry Keys" items={iocs.registry_keys} />
        </div>
      </CollapsibleSection>

      {/* Recommendations */}
      {recommendations.length > 0 && (
        <CollapsibleSection 
          title="Recommendations" 
          icon={<Shield className="w-6 h-6" />}
          count={recommendations.length}
          defaultOpen={true}
        >
          <div className="space-y-3">
            {recommendations.map((rec, idx) => (
              <RecommendationCard key={idx} rec={rec} />
            ))}
          </div>
        </CollapsibleSection>
      )}

      {/* Technical Details */}
      <CollapsibleSection 
        title="Technical Details" 
        icon={<FileText className="w-6 h-6" />}
      >
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-slate-700 p-3 rounded">
            <span className="block text-slate-400 text-xs">Format</span>
            <span className="font-mono text-cyan-300">{technical_details.file_format}</span>
          </div>
          <div className="bg-slate-700 p-3 rounded">
            <span className="block text-slate-400 text-xs">Architecture</span>
            <span className="font-mono text-purple-300">{technical_details.architecture}</span>
          </div>
          <div className="bg-slate-700 p-3 rounded">
            <span className="block text-slate-400 text-xs">Platform</span>
            <span className="font-mono text-yellow-300">{technical_details.platform}</span>
          </div>
          <div className="bg-slate-700 p-3 rounded">
            <span className="block text-slate-400 text-xs">Size</span>
            <span className="font-mono text-slate-200">
              {(technical_details.file_size / 1024).toFixed(1)} KB
            </span>
          </div>
          {technical_details.c2_protocol && (
            <div className="bg-slate-700 p-3 rounded">
              <span className="block text-slate-400 text-xs">C2 Protocol</span>
              <span className="font-mono text-red-300">{technical_details.c2_protocol}</span>
            </div>
          )}
          {technical_details.encryption && (
            <div className="bg-slate-700 p-3 rounded">
              <span className="block text-slate-400 text-xs">Encryption</span>
              <span className="font-mono text-orange-300">{technical_details.encryption}</span>
            </div>
          )}
          {technical_details.compiler && (
            <div className="bg-slate-700 p-3 rounded">
              <span className="block text-slate-400 text-xs">Compiler</span>
              <span className="font-mono text-slate-200">{technical_details.compiler}</span>
            </div>
          )}
        </div>
        
        {technical_details.capabilities.length > 0 && (
          <div className="mt-4">
            <h3 className="text-sm font-medium text-slate-400 mb-2">Capabilities</h3>
            <div className="flex flex-wrap gap-2">
              {technical_details.capabilities.map((cap, idx) => (
                <span key={idx} className="px-2 py-1 rounded text-xs bg-purple-900/50 text-purple-200">
                  {cap}
                </span>
              ))}
            </div>
          </div>
        )}
      </CollapsibleSection>

      {/* Data Sources */}
      <div className="bg-slate-800 p-4 rounded-lg border border-slate-700">
        <div className="flex items-center justify-between text-sm text-slate-400">
          <div className="flex gap-4">
            {data_sources.static_analysis && <span>✓ Static Analysis</span>}
            {data_sources.dynamic_analysis && <span>✓ Dynamic Analysis</span>}
            {data_sources.ghidra_analysis && <span>✓ Ghidra Analysis</span>}
            {data_sources.threat_intel && <span>✓ Threat Intel</span>}
          </div>
          <div>
            {data_sources.ghidra_functions_analyzed > 0 && (
              <span>{data_sources.ghidra_functions_analyzed} functions analyzed</span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
