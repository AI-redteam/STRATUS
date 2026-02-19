import React, { useState, useEffect } from 'react';
import type { WorkspaceInfo, ScopeInfo, GraphStats, RunInfo, ScopeCheckResult } from '../types/api';
import * as api from '../hooks/useWails';
import { Badge, statusBadge } from '../components/shared/Badge';
import { DataTable, Column } from '../components/shared/DataTable';
import { LoadingState, ErrorBanner, Spinner } from '../components/shared/Spinner';
import { formatDate, shortUUID } from '../lib/format';

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

  // Edit scope state
  const [editingScope, setEditingScope] = useState(false);
  const [newAccounts, setNewAccounts] = useState('');
  const [newRegions, setNewRegions] = useState('');
  const [scopeSaving, setScopeSaving] = useState(false);
  const [scopeError, setScopeError] = useState('');

  // Scope check state
  const [checkRegion, setCheckRegion] = useState('');
  const [checkAccount, setCheckAccount] = useState('');
  const [checkResult, setCheckResult] = useState<ScopeCheckResult | null>(null);

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

  const handleSaveScope = async () => {
    setScopeError('');
    setScopeSaving(true);
    try {
      const addAccounts = newAccounts.split(',').map(s => s.trim()).filter(Boolean);
      const addRegions = newRegions.split(',').map(s => s.trim()).filter(Boolean);
      const updated = await api.updateScope({
        add_accounts: addAccounts.length > 0 ? addAccounts : undefined,
        add_regions: addRegions.length > 0 ? addRegions : undefined,
      });
      setScope(updated);
      setEditingScope(false);
      setNewAccounts('');
      setNewRegions('');
    } catch (e: any) {
      const msg = typeof e === 'string' ? e : (e?.message || 'Failed to update scope');
      setScopeError(msg);
    }
    setScopeSaving(false);
  };

  const handleCheckScope = async () => {
    if (!checkRegion && !checkAccount) return;
    try {
      const result = await api.checkScope(checkRegion, checkAccount);
      setCheckResult(result);
    } catch (e: any) {
      setCheckResult({ in_scope: false, reason: typeof e === 'string' ? e : (e?.message || 'Check failed') });
    }
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
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-semibold">Scope</h3>
            <button
              onClick={() => setEditingScope(!editingScope)}
              className="btn-ghost text-xs"
            >
              {editingScope ? 'Cancel' : 'Edit Scope'}
            </button>
          </div>
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

          {/* Edit scope inline form */}
          {editingScope && (
            <div className="mt-4 pt-4 border-t border-stratus-border space-y-3">
              {scopeError && <ErrorBanner message={scopeError} />}
              <div>
                <label className="block text-xs text-stratus-muted uppercase mb-1">Add Account IDs</label>
                <input
                  type="text"
                  className="input-field font-mono text-sm"
                  placeholder="123456789012, 210987654321"
                  value={newAccounts}
                  onChange={e => setNewAccounts(e.target.value)}
                />
              </div>
              <div>
                <label className="block text-xs text-stratus-muted uppercase mb-1">Add Regions</label>
                <input
                  type="text"
                  className="input-field text-sm"
                  placeholder="us-east-1, eu-west-1"
                  value={newRegions}
                  onChange={e => setNewRegions(e.target.value)}
                />
              </div>
              <button
                onClick={handleSaveScope}
                disabled={scopeSaving || (!newAccounts.trim() && !newRegions.trim())}
                className="btn-primary text-xs flex items-center gap-2"
              >
                {scopeSaving && <Spinner size="sm" />}
                {scopeSaving ? 'Saving...' : 'Update Scope'}
              </button>
            </div>
          )}

          {/* Scope check */}
          <div className="mt-4 pt-4 border-t border-stratus-border">
            <h4 className="text-xs text-stratus-muted uppercase mb-2">Quick Scope Check</h4>
            <div className="flex items-center gap-2">
              <input
                type="text"
                className="input-field text-xs w-36"
                placeholder="Region"
                value={checkRegion}
                onChange={e => { setCheckRegion(e.target.value); setCheckResult(null); }}
              />
              <input
                type="text"
                className="input-field text-xs w-36 font-mono"
                placeholder="Account ID"
                value={checkAccount}
                onChange={e => { setCheckAccount(e.target.value); setCheckResult(null); }}
              />
              <button
                onClick={handleCheckScope}
                disabled={!checkRegion && !checkAccount}
                className="btn-ghost text-xs"
              >
                Check
              </button>
              {checkResult && (
                <Badge
                  label={checkResult.in_scope ? 'In Scope' : 'Out of Scope'}
                  variant={checkResult.in_scope ? 'green' : 'red'}
                />
              )}
            </div>
            {checkResult && !checkResult.in_scope && (
              <p className="text-xs text-red-400 mt-1">{checkResult.reason}</p>
            )}
          </div>
        </div>
      )}

      {/* Export */}
      <div className="card">
        <h3 className="text-sm font-semibold mb-3">Export</h3>
        <div className="flex gap-2">
          <button
            onClick={async () => {
              try {
                const result = await api.exportWorkspace({ format: 'json' });
                const blob = new Blob([result.content], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url; a.download = result.filename; a.click();
                URL.revokeObjectURL(url);
              } catch (e: any) {
                alert(typeof e === 'string' ? e : (e?.message || 'Export failed'));
              }
            }}
            className="btn-ghost text-xs border border-stratus-border"
          >
            Export JSON
          </button>
          <button
            onClick={async () => {
              try {
                const result = await api.exportWorkspace({ format: 'markdown' });
                const blob = new Blob([result.content], { type: 'text/markdown' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url; a.download = result.filename; a.click();
                URL.revokeObjectURL(url);
              } catch (e: any) {
                alert(typeof e === 'string' ? e : (e?.message || 'Export failed'));
              }
            }}
            className="btn-ghost text-xs border border-stratus-border"
          >
            Export Markdown
          </button>
        </div>
      </div>

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
