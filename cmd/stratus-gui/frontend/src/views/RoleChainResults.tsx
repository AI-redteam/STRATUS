import React, { useState, useEffect, useMemo } from 'react';
import type { RunInfo, RoleChainEntry, RoleChainAnalysis } from '../types/api';
import * as api from '../hooks/useWails';
import { Badge } from '../components/shared/Badge';
import { DetailPanel, DetailRow } from '../components/shared/DetailPanel';
import { DataTable, Column } from '../components/shared/DataTable';
import { LoadingState, ErrorBanner } from '../components/shared/Spinner';
import { formatDate, shortUUID, truncateARN } from '../lib/format';

const CHAIN_MODULE = 'com.stratus.sts.enumerate-roles-chain';

function depthBadge(depth: number) {
  if (depth === 1) return <Badge label="direct" variant="green" />;
  if (depth === 2) return <Badge label={`${depth} hops`} variant="yellow" />;
  return <Badge label={`${depth} hops`} variant="red" />;
}

function roleNameFromARN(arn: string): string {
  // arn:aws:iam::123456789012:role/RoleName or arn:aws:iam::123456789012:role/path/RoleName
  const parts = arn.split('/');
  return parts[parts.length - 1] || arn;
}

function accountFromARN(arn: string): string {
  const parts = arn.split(':');
  return parts.length >= 5 ? parts[4] : '?';
}

function parseChainAnalysis(run: RunInfo): RoleChainAnalysis | null {
  if (!run.output_json) return null;
  try {
    const raw = JSON.parse(run.output_json);
    return {
      roles_enumerated: raw.roles_enumerated ?? 0,
      assumable_roles: (raw.assumable_roles ?? []) as string[],
      chain_depth_reached: raw.chain_depth_reached ?? 0,
      trust_edges: raw.trust_edges ?? 0,
      chains: (raw.chains ?? []) as RoleChainEntry[],
    };
  } catch {
    return null;
  }
}

export function RoleChainResults() {
  const [runs, setRuns] = useState<RunInfo[]>([]);
  const [selectedRunUUID, setSelectedRunUUID] = useState('');
  const [analysis, setAnalysis] = useState<RoleChainAnalysis | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  // Filters
  const [depthFilter, setDepthFilter] = useState('');
  const [roleSearch, setRoleSearch] = useState('');

  // Detail panel
  const [selectedChain, setSelectedChain] = useState<RoleChainEntry | null>(null);

  useEffect(() => { loadRuns(); }, []);

  const loadRuns = async () => {
    setLoading(true);
    setError('');
    try {
      const allRuns = await api.listRuns(CHAIN_MODULE, '');
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
      setAnalysis(parseChainAnalysis(run));
    } catch (e: any) {
      setError(typeof e === 'string' ? e : (e?.message || 'Failed to load run detail'));
    }
  };

  const handleRunChange = async (uuid: string) => {
    setSelectedRunUUID(uuid);
    setAnalysis(null);
    setSelectedChain(null);
    await loadRunDetail(uuid);
  };

  // Unique depths for filter
  const depths = useMemo(() => {
    if (!analysis) return [];
    return [...new Set(analysis.chains.map(c => c.depth))].sort();
  }, [analysis]);

  // Filter chains
  const filteredChains = useMemo(() => {
    if (!analysis) return [];
    return analysis.chains.filter(c => {
      if (depthFilter && c.depth !== parseInt(depthFilter)) return false;
      if (roleSearch) {
        const q = roleSearch.toLowerCase();
        if (!c.target_role.toLowerCase().includes(q) &&
            !c.path.some(p => p.toLowerCase().includes(q))) return false;
      }
      return true;
    });
  }, [analysis, depthFilter, roleSearch]);

  // Group chains by depth for summary
  const depthSummary = useMemo(() => {
    if (!analysis) return [];
    const grouped: Record<number, number> = {};
    for (const c of analysis.chains) {
      grouped[c.depth] = (grouped[c.depth] || 0) + 1;
    }
    return Object.entries(grouped)
      .map(([d, count]) => ({ depth: parseInt(d), count }))
      .sort((a, b) => a.depth - b.depth);
  }, [analysis]);

  const columns: Column<RoleChainEntry>[] = [
    {
      key: 'depth',
      header: 'Depth',
      width: '90px',
      render: (row) => depthBadge(row.depth),
    },
    {
      key: 'target_role',
      header: 'Target Role',
      render: (row) => (
        <div>
          <span className="font-mono text-sm">{roleNameFromARN(row.target_role)}</span>
          <span className="text-xs text-stratus-muted ml-2">{accountFromARN(row.target_role)}</span>
        </div>
      ),
    },
    {
      key: 'path',
      header: 'Chain',
      render: (row) => (
        <div className="flex items-center gap-1 overflow-hidden">
          {row.path.map((arn, i) => (
            <React.Fragment key={i}>
              {i > 0 && <span className="text-stratus-muted text-xs shrink-0">-&gt;</span>}
              <span className="text-xs font-mono truncate" title={arn}>
                {roleNameFromARN(arn)}
              </span>
            </React.Fragment>
          ))}
        </div>
      ),
    },
  ];

  if (loading) return <LoadingState message="Loading role chain analysis..." />;
  if (error) return <ErrorBanner message={error} onRetry={loadRuns} />;

  if (runs.length === 0) {
    return (
      <div className="space-y-6">
        <h1 className="text-xl font-bold">Role Chain Discovery</h1>
        <div className="card text-center py-16">
          <svg className="w-12 h-12 mx-auto text-stratus-muted mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4" />
          </svg>
          <p className="text-stratus-muted text-sm mb-4">No role chain discovery results yet.</p>
          <p className="text-stratus-muted text-xs">
            Run the <span className="font-mono text-stratus-accent">com.stratus.sts.enumerate-roles-chain</span> module
            from the Modules view to discover lateral movement paths.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header with run selector */}
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-xl font-bold">Role Chain Discovery</h1>
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
              <p className="text-xs text-stratus-muted uppercase">Roles Enumerated</p>
              <p className="text-2xl font-bold mt-1">{analysis.roles_enumerated}</p>
            </div>
            <div className="card">
              <p className="text-xs text-stratus-muted uppercase">Assumable Roles</p>
              <p className="text-2xl font-bold mt-1 text-amber-400">{analysis.assumable_roles.length}</p>
            </div>
            <div className="card">
              <p className="text-xs text-stratus-muted uppercase">Max Chain Depth</p>
              <p className="text-2xl font-bold mt-1">{analysis.chain_depth_reached}</p>
            </div>
            <div className="card">
              <p className="text-xs text-stratus-muted uppercase">Trust Edges</p>
              <p className="text-2xl font-bold mt-1 text-stratus-accent">{analysis.trust_edges}</p>
            </div>
          </div>

          {/* Directly assumable roles */}
          {analysis.assumable_roles.length > 0 && (
            <div className="card">
              <h3 className="text-sm font-semibold mb-3">
                Directly Assumable Roles
                <span className="text-xs text-stratus-muted font-normal ml-2">
                  ({analysis.assumable_roles.length} role{analysis.assumable_roles.length !== 1 ? 's' : ''})
                </span>
              </h3>
              <div className="flex flex-wrap gap-2">
                {analysis.assumable_roles.map(arn => (
                  <span key={arn} className="inline-flex items-center px-2.5 py-1 bg-amber-900/30 border border-amber-700 rounded text-xs font-mono text-amber-300" title={arn}>
                    {roleNameFromARN(arn)}
                    <span className="text-amber-500/60 ml-1.5">{accountFromARN(arn)}</span>
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Depth distribution */}
          {depthSummary.length > 0 && (
            <div className="card">
              <h3 className="text-sm font-semibold mb-3">Chains by Depth</h3>
              <div className="flex items-end gap-3 h-24">
                {depthSummary.map(({ depth, count }) => {
                  const maxCount = Math.max(...depthSummary.map(d => d.count));
                  const height = maxCount > 0 ? Math.max((count / maxCount) * 100, 12) : 12;
                  return (
                    <div key={depth} className="flex flex-col items-center gap-1 flex-1">
                      <span className="text-xs text-stratus-muted">{count}</span>
                      <div
                        className={`w-full rounded-t ${depth === 1 ? 'bg-emerald-500/60' : depth === 2 ? 'bg-amber-500/60' : 'bg-red-500/60'}`}
                        style={{ height: `${height}%` }}
                      />
                      <span className="text-xs text-stratus-muted">
                        {depth === 1 ? 'Direct' : `${depth} hops`}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Filters */}
          <div className="flex items-center gap-2">
            <input
              type="text"
              className="input-field w-48"
              placeholder="Search role..."
              value={roleSearch}
              onChange={e => setRoleSearch(e.target.value)}
            />
            <select
              className="input-field w-32"
              value={depthFilter}
              onChange={e => setDepthFilter(e.target.value)}
            >
              <option value="">All Depths</option>
              {depths.map(d => (
                <option key={d} value={d}>{d === 1 ? 'Direct' : `${d} hops`}</option>
              ))}
            </select>
            <span className="text-xs text-stratus-muted ml-auto">
              {filteredChains.length} of {analysis.chains.length} chains
            </span>
          </div>

          {/* Chains table */}
          <DataTable
            columns={columns}
            data={filteredChains}
            onRowClick={setSelectedChain}
            emptyMessage="No chains match the current filters"
            keyField="target_role"
          />
        </>
      )}

      {/* Chain detail panel */}
      <DetailPanel
        open={!!selectedChain}
        onClose={() => setSelectedChain(null)}
        title="Role Assumption Chain"
      >
        {selectedChain && (
          <>
            <div className="flex items-center gap-2 mb-2">
              {depthBadge(selectedChain.depth)}
            </div>

            <DetailRow label="Target Role" value={roleNameFromARN(selectedChain.target_role)} mono />
            <DetailRow label="Target ARN" value={selectedChain.target_role} mono />
            <DetailRow label="Account" value={accountFromARN(selectedChain.target_role)} mono />
            <DetailRow label="Chain Depth" value={`${selectedChain.depth} hop${selectedChain.depth !== 1 ? 's' : ''}`} />

            {/* Visual chain path */}
            <div>
              <dt className="text-xs text-stratus-muted uppercase mb-2">Assumption Path</dt>
              <div className="space-y-0">
                {selectedChain.path.map((arn, i) => (
                  <div key={i}>
                    <div className={`flex items-center gap-2 p-2 rounded text-xs ${
                      i === 0 ? 'bg-blue-900/30 border border-blue-700' :
                      i === selectedChain.path.length - 1 ? 'bg-amber-900/30 border border-amber-700' :
                      'bg-stratus-bg'
                    }`}>
                      <span className="w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold shrink-0 bg-stratus-surface border border-stratus-border">
                        {i + 1}
                      </span>
                      <div className="min-w-0">
                        <p className="font-mono font-medium truncate" title={arn}>
                          {roleNameFromARN(arn)}
                        </p>
                        <p className="text-stratus-muted truncate" title={arn}>{arn}</p>
                      </div>
                      {i === 0 && <Badge label="origin" variant="blue" className="ml-auto shrink-0" />}
                      {i === selectedChain.path.length - 1 && i > 0 && <Badge label="target" variant="yellow" className="ml-auto shrink-0" />}
                    </div>
                    {i < selectedChain.path.length - 1 && (
                      <div className="flex justify-center py-0.5">
                        <svg className="w-4 h-4 text-stratus-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 14l-7 7m0 0l-7-7m7 7V3" />
                        </svg>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>

            <div className="mt-4 pt-4 border-t border-stratus-border text-xs text-stratus-muted">
              {selectedChain.depth === 1 ? (
                <span>This role is directly assumable from the current identity via <strong className="text-stratus-text">sts:AssumeRole</strong>.</span>
              ) : (
                <span>
                  This role requires a <strong className="text-stratus-text">{selectedChain.depth}-hop</strong> assumption chain.
                  Each step requires the previous role to have <strong className="text-stratus-text">sts:AssumeRole</strong> permission
                  and the target role's trust policy to allow the assumption.
                </span>
              )}
            </div>
          </>
        )}
      </DetailPanel>
    </div>
  );
}
