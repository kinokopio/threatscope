import { 
  Activity, 
  Network, 
  Shield, 
  Terminal, 
  FileText,
  AlertTriangle,
  Globe,
  Cpu
} from 'lucide-react';

interface ProcessNode {
  pid: number;
  name: string;
  cmdline: string;
  children: ProcessNode[];
}

interface SecurityEvent {
  event: string;
  process: string;
  pid: number;
  description: string;
  severity: string;
  count: number;
}

interface DnsQuery {
  domain: string;
  response: string;
  count: number;
}

interface NetworkSummary {
  dns_queries: DnsQuery[];
  connections: Array<{
    remote_ip: string;
    remote_port: number;
    protocol: string;
    count: number;
  }>;
  http_requests: Array<{
    method: string;
    host: string;
    uri: string;
    count: number;
  }>;
  total_dns_queries: number;
  total_connections: number;
}

interface SyscallSummary {
  by_type: Record<string, number>;
  by_process: Record<string, string[]>;
  total_count: number;
  unique_types: string[];
}

interface DynamicAnalysisData {
  success: boolean;
  method: string;
  duration_seconds: number;
  process_tree: ProcessNode[];
  network_summary: NetworkSummary;
  security_events: SecurityEvent[];
  syscall_summary: SyscallSummary;
  file_activity: {
    created: string[];
    modified: string[];
    deleted: string[];
    executed: string[];
  };
  raw_events_count: number;
  event_types: string[];
  error?: string;
}

interface DynamicAnalysisViewProps {
  data: DynamicAnalysisData;
}

function ProcessTree({ nodes, depth = 0 }: { nodes: ProcessNode[]; depth?: number }) {
  if (!nodes || nodes.length === 0) return null;

  return (
    <div className={depth > 0 ? "ml-4 border-l border-slate-700 pl-3" : ""}>
      {nodes.map((node, idx) => (
        <div key={`${node.pid}-${idx}`} className="py-1">
          <div className="flex items-center gap-2">
            <Cpu className="w-3 h-3 text-cyan-400 flex-shrink-0" />
            <span className="text-slate-400 text-xs">[{node.pid}]</span>
            <span className="text-emerald-400 font-medium text-sm">{node.name}</span>
          </div>
          {node.cmdline && (
            <div className="ml-5 text-xs text-slate-500 font-mono truncate max-w-md" title={node.cmdline}>
              {node.cmdline}
            </div>
          )}
          {node.children && node.children.length > 0 && (
            <ProcessTree nodes={node.children} depth={depth + 1} />
          )}
        </div>
      ))}
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border-red-500/30",
    high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  };
  
  return (
    <span className={`px-2 py-0.5 text-xs rounded border ${colors[severity] || colors.low}`}>
      {severity}
    </span>
  );
}

export default function DynamicAnalysisView({ data }: DynamicAnalysisViewProps) {
  if (!data) return null;

  const hasSecurityEvents = data.security_events && data.security_events.length > 0;
  const hasNetwork = data.network_summary && (
    data.network_summary.dns_queries?.length > 0 ||
    data.network_summary.connections?.length > 0 ||
    data.network_summary.http_requests?.length > 0
  );
  const hasProcessTree = data.process_tree && data.process_tree.length > 0;
  const hasSyscalls = data.syscall_summary && data.syscall_summary.total_count > 0;
  const hasFileActivity = data.file_activity && (
    data.file_activity.created?.length > 0 ||
    data.file_activity.modified?.length > 0 ||
    data.file_activity.deleted?.length > 0
  );

  return (
    <div className="space-y-4">
      {/* Header Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="bg-slate-800/50 rounded-lg p-3 border border-slate-700/50">
          <div className="text-slate-400 text-xs mb-1">Duration</div>
          <div className="text-white font-medium">{data.duration_seconds.toFixed(1)}s</div>
        </div>
        <div className="bg-slate-800/50 rounded-lg p-3 border border-slate-700/50">
          <div className="text-slate-400 text-xs mb-1">Events Captured</div>
          <div className="text-white font-medium">{data.raw_events_count}</div>
        </div>
        <div className="bg-slate-800/50 rounded-lg p-3 border border-slate-700/50">
          <div className="text-slate-400 text-xs mb-1">Security Alerts</div>
          <div className={`font-medium ${hasSecurityEvents ? 'text-orange-400' : 'text-emerald-400'}`}>
            {data.security_events?.length || 0}
          </div>
        </div>
        <div className="bg-slate-800/50 rounded-lg p-3 border border-slate-700/50">
          <div className="text-slate-400 text-xs mb-1">DNS Queries</div>
          <div className="text-white font-medium">{data.network_summary?.dns_queries?.length || 0}</div>
        </div>
      </div>

      {/* Security Events */}
      {hasSecurityEvents && (
        <div className="bg-slate-800/50 rounded-lg border border-slate-700/50 overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-700/50 flex items-center gap-2">
            <Shield className="w-4 h-4 text-orange-400" />
            <span className="font-medium text-white">Security Events</span>
            <span className="text-xs text-slate-400">({data.security_events.length})</span>
          </div>
          <div className="p-4 space-y-3">
            {data.security_events.map((event, idx) => (
              <div key={idx} className="bg-slate-900/50 rounded-lg p-3">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-orange-400" />
                    <span className="text-orange-400 font-medium text-sm">{event.event}</span>
                    {event.count > 1 && (
                      <span className="text-xs text-slate-500">×{event.count}</span>
                    )}
                  </div>
                  <SeverityBadge severity={event.severity} />
                </div>
                <div className="text-xs text-slate-400 mb-1">
                  Process: <span className="text-slate-300">{event.process}</span> (PID: {event.pid})
                </div>
                {event.description && (
                  <div className="text-xs text-slate-500 mt-2">{event.description}</div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Process Tree */}
      {hasProcessTree && (
        <div className="bg-slate-800/50 rounded-lg border border-slate-700/50 overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-700/50 flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            <span className="font-medium text-white">Process Tree</span>
          </div>
          <div className="p-4">
            <ProcessTree nodes={data.process_tree} />
          </div>
        </div>
      )}

      {/* Network Activity */}
      {hasNetwork && (
        <div className="bg-slate-800/50 rounded-lg border border-slate-700/50 overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-700/50 flex items-center gap-2">
            <Network className="w-4 h-4 text-purple-400" />
            <span className="font-medium text-white">Network Activity</span>
          </div>
          <div className="p-4 space-y-4">
            {/* DNS Queries */}
            {data.network_summary.dns_queries?.length > 0 && (
              <div>
                <div className="text-xs text-slate-400 mb-2 flex items-center gap-1">
                  <Globe className="w-3 h-3" />
                  DNS Queries ({data.network_summary.total_dns_queries} total)
                </div>
                <div className="space-y-1">
                  {data.network_summary.dns_queries.map((query, idx) => (
                    <div key={idx} className="flex items-center justify-between bg-slate-900/50 rounded px-3 py-2">
                      <span className="text-cyan-400 font-mono text-sm">{query.domain}</span>
                      <div className="flex items-center gap-2">
                        {query.response && (
                          <span className="text-slate-500 text-xs">{query.response}</span>
                        )}
                        {query.count > 1 && (
                          <span className="text-xs text-slate-600">×{query.count}</span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Connections */}
            {data.network_summary.connections?.length > 0 && (
              <div>
                <div className="text-xs text-slate-400 mb-2">TCP Connections</div>
                <div className="space-y-1">
                  {data.network_summary.connections.map((conn, idx) => (
                    <div key={idx} className="flex items-center justify-between bg-slate-900/50 rounded px-3 py-2">
                      <span className="text-purple-400 font-mono text-sm">
                        {conn.remote_ip}:{conn.remote_port}
                      </span>
                      <span className="text-xs text-slate-500">{conn.protocol}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* HTTP Requests */}
            {data.network_summary.http_requests?.length > 0 && (
              <div>
                <div className="text-xs text-slate-400 mb-2">HTTP Requests</div>
                <div className="space-y-1">
                  {data.network_summary.http_requests.map((req, idx) => (
                    <div key={idx} className="bg-slate-900/50 rounded px-3 py-2">
                      <span className="text-yellow-400 font-mono text-xs">{req.method}</span>
                      <span className="text-slate-300 font-mono text-sm ml-2">{req.host}{req.uri}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Syscall Summary */}
      {hasSyscalls && (
        <div className="bg-slate-800/50 rounded-lg border border-slate-700/50 overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-700/50 flex items-center gap-2">
            <Terminal className="w-4 h-4 text-emerald-400" />
            <span className="font-medium text-white">System Calls</span>
            <span className="text-xs text-slate-400">({data.syscall_summary.total_count} total)</span>
          </div>
          <div className="p-4">
            <div className="flex flex-wrap gap-2">
              {Object.entries(data.syscall_summary.by_type).map(([name, count]) => (
                <div 
                  key={name}
                  className="bg-slate-900/50 rounded px-2 py-1 text-xs flex items-center gap-1"
                >
                  <span className="text-emerald-400 font-mono">{name}</span>
                  <span className="text-slate-500">×{count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* File Activity */}
      {hasFileActivity && (
        <div className="bg-slate-800/50 rounded-lg border border-slate-700/50 overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-700/50 flex items-center gap-2">
            <FileText className="w-4 h-4 text-yellow-400" />
            <span className="font-medium text-white">File Activity</span>
          </div>
          <div className="p-4 space-y-3">
            {data.file_activity.created?.length > 0 && (
              <div>
                <div className="text-xs text-emerald-400 mb-1">Created</div>
                <div className="space-y-1">
                  {data.file_activity.created.map((path, idx) => (
                    <div key={idx} className="text-xs text-slate-300 font-mono bg-slate-900/50 rounded px-2 py-1">
                      {path}
                    </div>
                  ))}
                </div>
              </div>
            )}
            {data.file_activity.modified?.length > 0 && (
              <div>
                <div className="text-xs text-yellow-400 mb-1">Modified</div>
                <div className="space-y-1">
                  {data.file_activity.modified.map((path, idx) => (
                    <div key={idx} className="text-xs text-slate-300 font-mono bg-slate-900/50 rounded px-2 py-1">
                      {path}
                    </div>
                  ))}
                </div>
              </div>
            )}
            {data.file_activity.deleted?.length > 0 && (
              <div>
                <div className="text-xs text-red-400 mb-1">Deleted</div>
                <div className="space-y-1">
                  {data.file_activity.deleted.map((path, idx) => (
                    <div key={idx} className="text-xs text-slate-300 font-mono bg-slate-900/50 rounded px-2 py-1">
                      {path}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Event Types */}
      {data.event_types && data.event_types.length > 0 && (
        <div className="text-xs text-slate-500">
          <span className="text-slate-400">Event types captured:</span>{' '}
          {data.event_types.join(', ')}
        </div>
      )}
    </div>
  );
}
