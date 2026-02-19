import React, { useState, useEffect, useMemo } from 'react';
import type { RunInfo, PrivEscFinding, PrivEscAnalysis } from '../types/api';
import * as api from '../hooks/useWails';
import { Badge } from '../components/shared/Badge';
import { DetailPanel, DetailRow } from '../components/shared/DetailPanel';
import { DataTable, Column } from '../components/shared/DataTable';
import { LoadingState, ErrorBanner } from '../components/shared/Spinner';
import { formatDate, shortUUID, truncateARN } from '../lib/format';

const ANALYZER_MODULE = 'com.stratus.iam.policy-analyzer';

function severityBadge(severity: string) {
  const map: Record<string, 'red' | 'yellow'> = {
    critical: 'red',
    high: 'yellow',
  };
  return <Badge label={severity} variant={map[severity] || 'gray'} />;
}

function parseAnalysis(run: RunInfo): PrivEscAnalysis | null {
  if (!run.output_json) return null;
  try {
    const raw = JSON.parse(run.output_json);
    return {
      principals_scanned: raw.principals_scanned ?? 0,
      privesc_paths: (raw.privesc_paths ?? []) as PrivEscFinding[],
      high_risk_count: raw.high_risk_count ?? 0,
      admin_principals: (raw.admin_principals ?? []) as string[],
    };
  } catch {
    return null;
  }
}

export function PrivEscResults() {
  const [runs, setRuns] = useState<RunInfo[]>([]);
  const [selectedRunUUID, setSelectedRunUUID] = useState('');
  const [analysis, setAnalysis] = useState<PrivEscAnalysis | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  // Filters
  const [severityFilter, setSeverityFilter] = useState('');
  const [findingFilter, setFindingFilter] = useState('');
  const [principalSearch, setPrincipalSearch] = useState('');

  // Detail panel
  const [selectedFinding, setSelectedFinding] = useState<PrivEscFinding | null>(null);

  useEffect(() => { loadRuns(); }, []);

  const loadRuns = async () => {
    setLoading(true);
    setError('');
    try {
      const allRuns = await api.listRuns(ANALYZER_MODULE, '');
      const successRuns = (allRuns || []).filter(r => r.status === 'success');
      setRuns(successRuns);
      if (successRuns.length > 0) {
        const latest = successRuns[0];
        setSelectedRunUUID(latest.uuid);
        await loadRunDetail(latest.uuid);
      }
    } catch (e: any) {
      setError(typeof e === 'string' ? e : (e?.message || 'Failed to load runs'));
    }
    setLoading(false);
  };

  const loadRunDetail = async (uuid: string) => {
    try {
      const run = await api.getRunStatus(uuid);
      setAnalysis(parseAnalysis(run));
    } catch (e: any) {
      setError(typeof e === 'string' ? e : (e?.message || 'Failed to load run detail'));
    }
  };

  const handleRunChange = async (uuid: string) => {
    setSelectedRunUUID(uuid);
    setAnalysis(null);
    setSelectedFinding(null);
    await loadRunDetail(uuid);
  };

  // Derive unique finding types for filter
  const findingTypes = useMemo(() => {
    if (!analysis) return [];
    return [...new Set(analysis.privesc_paths.map(f => f.finding))].sort();
  }, [analysis]);

  // Filter paths
  const filteredPaths = useMemo(() => {
    if (!analysis) return [];
    return analysis.privesc_paths.filter(f => {
      if (severityFilter && f.severity !== severityFilter) return false;
      if (findingFilter && f.finding !== findingFilter) return false;
      if (principalSearch) {
        const q = principalSearch.toLowerCase();
        if (!f.principal_name.toLowerCase().includes(q) &&
            !f.principal_arn.toLowerCase().includes(q)) return false;
      }
      return true;
    });
  }, [analysis, severityFilter, findingFilter, principalSearch]);

  // Group findings by principal for summary
  const principalSummary = useMemo(() => {
    if (!analysis) return [];
    const grouped: Record<string, { arn: string; type: string; count: number; critical: number }> = {};
    for (const f of analysis.privesc_paths) {
      if (!grouped[f.principal_arn]) {
        grouped[f.principal_arn] = { arn: f.principal_arn, type: f.principal_type, count: 0, critical: 0 };
      }
      grouped[f.principal_arn].count++;
      if (f.severity === 'critical') grouped[f.principal_arn].critical++;
    }
    return Object.values(grouped).sort((a, b) => b.critical - a.critical || b.count - a.count);
  }, [analysis]);

  const columns: Column<PrivEscFinding>[] = [
    {
      key: 'severity',
      header: 'Severity',
      width: '90px',
      render: (row) => severityBadge(row.severity),
    },
    {
      key: 'principal_name',
      header: 'Principal',
      render: (row) => (
        <div>
          <span className="font-mono text-sm">{row.principal_name}</span>
          <Badge label={row.principal_type} variant={row.principal_type === 'role' ? 'purple' : 'blue'} className="ml-2" />
        </div>
      ),
    },
    {
      key: 'finding',
      header: 'Finding',
      render: (row) => <span className="font-mono text-xs">{row.finding}</span>,
    },
    {
      key: 'description',
      header: 'Description',
      render: (row) => <span className="text-xs text-stratus-muted line-clamp-2">{row.description}</span>,
    },
    {
      key: 'reference',
      header: 'MITRE',
      width: '70px',
      render: (row) => <span className="text-xs text-stratus-muted">{row.reference}</span>,
    },
  ];

  if (loading) return <LoadingState message="Loading privilege escalation analysis..." />;
  if (error) return <ErrorBanner message={error} onRetry={loadRuns} />;

  if (runs.length === 0) {
    return (
      <div className="space-y-6">
        <h1 className="text-xl font-bold">Privilege Escalation Analysis</h1>
        <div className="card text-center py-16">
          <svg className="w-12 h-12 mx-auto text-stratus-muted mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
          </svg>
          <p className="text-stratus-muted text-sm mb-4">No privilege escalation analysis results yet.</p>
          <p className="text-stratus-muted text-xs">
            Run the <span className="font-mono text-stratus-accent">com.stratus.iam.policy-analyzer</span> module
            from the Modules view to scan for privilege escalation paths.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header with run selector */}
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-xl font-bold">Privilege Escalation Analysis</h1>
        <div className="flex items-center gap-2">
          <label className="text-xs text-stratus-muted">Run:</label>
          <select
            className="input-field w-64"
            value={selectedRunUUID}
            onChange={e => handleRunChange(e.target.value)}
          >
            {runs.map(r => (
              <option key={r.uuid} value={r.uuid}>
                {shortUUID(r.uuid)} — {formatDate(r.started_at)}
              </option>
            ))}
          </select>
        </div>
      </div>

      {analysis && (
        <>
          {/* Summary stat cards */}
          <div className="grid grid-cols-4 gap-4">
            <div className="card">
              <p className="text-xs text-stratus-muted uppercase">Principals Scanned</p>
              <p className="text-2xl font-bold mt-1">{analysis.principals_scanned}</p>
            </div>
            <div className="card">
              <p className="text-xs text-stratus-muted uppercase">PrivEsc Paths Found</p>
              <p className="text-2xl font-bold mt-1 text-amber-400">{analysis.privesc_paths.length}</p>
            </div>
            <div className="card">
              <p className="text-xs text-stratus-muted uppercase">At-Risk Principals</p>
              <p className="text-2xl font-bold mt-1 text-red-400">{analysis.high_risk_count}</p>
            </div>
            <div className="card">
              <p className="text-xs text-stratus-muted uppercase">Full Admin</p>
              <p className="text-2xl font-bold mt-1 text-red-400">{analysis.admin_principals.length}</p>
            </div>
          </div>

          {/* Admin principals banner */}
          {analysis.admin_principals.length > 0 && (
            <div className="bg-red-900/20 border border-red-700 rounded-lg p-4">
              <h3 className="text-sm font-semibold text-red-400 mb-2">
                Principals with Full Admin Access
              </h3>
              <div className="flex flex-wrap gap-2">
                {analysis.admin_principals.map(arn => (
                  <span key={arn} className="inline-flex items-center px-2.5 py-1 bg-red-900/40 border border-red-700 rounded text-xs font-mono text-red-300">
                    {truncateARN(arn, 60)}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Principal risk summary */}
          {principalSummary.length > 0 && (
            <div className="card">
              <h3 className="text-sm font-semibold mb-3">Risk by Principal</h3>
              <div className="space-y-2 max-h-48 overflow-y-auto">
                {principalSummary.map(p => (
                  <div key={p.arn} className="flex items-center gap-3 text-xs">
                    <Badge label={p.type} variant={p.type === 'role' ? 'purple' : 'blue'} />
                    <span className="font-mono flex-1 truncate" title={p.arn}>
                      {truncateARN(p.arn, 50)}
                    </span>
                    <span className="text-stratus-muted">{p.count} finding{p.count !== 1 ? 's' : ''}</span>
                    {p.critical > 0 && (
                      <Badge label={`${p.critical} critical`} variant="red" />
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Filters */}
          <div className="flex items-center gap-2">
            <input
              type="text"
              className="input-field w-48"
              placeholder="Search principal..."
              value={principalSearch}
              onChange={e => setPrincipalSearch(e.target.value)}
            />
            <select
              className="input-field w-32"
              value={severityFilter}
              onChange={e => setSeverityFilter(e.target.value)}
            >
              <option value="">All Severity</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
            </select>
            <select
              className="input-field w-48"
              value={findingFilter}
              onChange={e => setFindingFilter(e.target.value)}
            >
              <option value="">All Findings</option>
              {findingTypes.map(f => <option key={f} value={f}>{f}</option>)}
            </select>
            <span className="text-xs text-stratus-muted ml-auto">
              {filteredPaths.length} of {analysis.privesc_paths.length} findings
            </span>
          </div>

          {/* Findings table */}
          <DataTable
            columns={columns}
            data={filteredPaths}
            onRowClick={setSelectedFinding}
            emptyMessage="No findings match the current filters"
            keyField="principal_arn"
          />
        </>
      )}

      {/* Finding detail panel */}
      <DetailPanel
        open={!!selectedFinding}
        onClose={() => setSelectedFinding(null)}
        title="Privilege Escalation Finding"
      >
        {selectedFinding && (
          <>
            <div className="flex items-center gap-2 mb-2">
              {severityBadge(selectedFinding.severity)}
              <Badge label={selectedFinding.principal_type} variant={selectedFinding.principal_type === 'role' ? 'purple' : 'blue'} />
            </div>

            <DetailRow label="Finding" value={selectedFinding.finding} mono />
            <DetailRow label="Principal" value={selectedFinding.principal_name} mono />
            <DetailRow label="Principal ARN" value={selectedFinding.principal_arn} mono />
            <DetailRow label="Description" value={selectedFinding.description} />

            <div>
              <dt className="text-xs text-stratus-muted uppercase mb-2">Required Actions</dt>
              <div className="space-y-1">
                {selectedFinding.required_actions.map(action => (
                  <div key={action} className="text-xs font-mono bg-stratus-bg rounded px-2 py-1">
                    {action}
                  </div>
                ))}
              </div>
            </div>

            <DetailRow label="MITRE ATT&CK" value={selectedFinding.reference} mono />

            <div className="mt-4 pt-4 border-t border-stratus-border text-xs text-stratus-muted">
              This principal can escalate privileges via the <strong className="text-stratus-text">{selectedFinding.finding}</strong> technique.
              {selectedFinding.severity === 'critical' && (
                <span className="text-red-400"> This is a critical finding — the principal has or can obtain full administrative access.</span>
              )}
            </div>
          </>
        )}
      </DetailPanel>
    </div>
  );
}
