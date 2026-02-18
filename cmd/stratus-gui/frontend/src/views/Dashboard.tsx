import React, { useState, useEffect } from 'react';
import type { WorkspaceInfo, ScopeInfo, GraphStats, RunInfo } from '../types/api';
import * as api from '../hooks/useWails';
import { Badge } from '../components/shared/Badge';
import { DataTable, Column } from '../components/shared/DataTable';
import { LoadingState, ErrorBanner } from '../components/shared/Spinner';
import { formatDate, shortUUID, statusBadge } from '../lib/format';

interface Props {
  onRefresh: () => void;
}

export function Dashboard({ onRefresh }: Props) {
  const [workspace, setWorkspace] = useState<WorkspaceInfo | null>(null);
  const [scope, setScope] = useState<ScopeInfo | null>(null);
  const [graphStats, setGraphStats] = useState<GraphStats | null>(null);
  const [runs, setRuns] = useState<RunInfo[]>([]);
  const [identityCount, setIdentityCount] = useState(0);
  const [sessionCount, setSessionCount] = useState(0);
  const [auditValid, setAuditValid] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    loadDashboard();
  }, []);

  const loadDashboard = async () => {
    setLoading(true);
    setError('');
    try {
      const [ws, sc, gs, r, ids, sess, audit] = await Promise.all([
        api.getWorkspace(),
        api.getScopeInfo(),
        api.getGraphStats(),
        api.listRuns('', ''),
        api.listIdentities(),
        api.listSessions(),
        api.verifyAuditChain(),
      ]);
      setWorkspace(ws);
      setScope(sc);
      setGraphStats(gs);
      setRuns(r?.slice(0, 10) || []);
      setIdentityCount(ids?.length || 0);
      setSessionCount(sess?.length || 0);
      setAuditValid(audit?.valid ?? null);
    } catch (e: any) {
      setError(e?.message || 'Failed to load dashboard');
    }
    setLoading(false);
  };

  if (loading) return <LoadingState message="Loading dashboard..." />;
  if (error) return <ErrorBanner message={error} onRetry={loadDashboard} />;

  const runColumns: Column<RunInfo>[] = [
    { key: 'uuid', header: 'Run', render: r => <span className="font-mono text-xs">{shortUUID(r.uuid)}</span> },
    { key: 'module_id', header: 'Module', render: r => <span className="text-xs">{r.module_id.split('.').pop()}</span> },
    { key: 'status', header: 'Status', render: r => statusBadge(r.status) },
    { key: 'started_at', header: 'Started', render: r => <span className="text-xs text-stratus-muted">{formatDate(r.started_at)}</span> },
  ];

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-bold">Dashboard</h1>

      {/* Workspace card */}
      {workspace && (
        <div className="card">
          <div className="flex items-start justify-between">
            <div>
              <h2 className="text-lg font-semibold">{workspace.name}</h2>
              {workspace.description && (
                <p className="text-sm text-stratus-muted mt-1">{workspace.description}</p>
              )}
              <p className="text-xs text-stratus-muted mt-2 font-mono">{shortUUID(workspace.uuid)} &middot; {formatDate(workspace.created_at)}</p>
            </div>
            {auditValid !== null && (
              <Badge
                label={auditValid ? 'Chain Valid' : 'Chain Broken'}
                variant={auditValid ? 'green' : 'red'}
              />
            )}
          </div>
        </div>
      )}

      {/* Stat cards */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard label="Identities" value={identityCount} color="text-blue-400" />
        <StatCard label="Sessions" value={sessionCount} color="text-emerald-400" />
        <StatCard label="Graph Nodes" value={graphStats?.nodes || 0} color="text-purple-400" />
        <StatCard label="Module Runs" value={runs?.length || 0} color="text-amber-400" />
      </div>

      {/* Scope display */}
      {scope && (
        <div className="card">
          <h3 className="text-sm font-semibold mb-3">Scope</h3>
          <div className="flex flex-wrap gap-2">
            {scope.account_ids?.map(id => (
              <Badge key={id} label={`Account: ${id}`} variant="blue" />
            ))}
            {scope.regions?.map(r => (
              <Badge key={r} label={r} variant="purple" />
            ))}
            {scope.partition && <Badge label={`Partition: ${scope.partition}`} variant="gray" />}
            {!scope.account_ids?.length && !scope.regions?.length && (
              <span className="text-xs text-stratus-muted">No scope restrictions configured</span>
            )}
          </div>
        </div>
      )}

      {/* Recent runs */}
      <div className="card">
        <h3 className="text-sm font-semibold mb-3">Recent Runs</h3>
        <DataTable columns={runColumns} data={runs} emptyMessage="No module runs yet" />
      </div>
    </div>
  );
}

function StatCard({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="card">
      <p className="text-xs text-stratus-muted uppercase">{label}</p>
      <p className={`text-2xl font-bold mt-1 ${color}`}>{value}</p>
    </div>
  );
}
