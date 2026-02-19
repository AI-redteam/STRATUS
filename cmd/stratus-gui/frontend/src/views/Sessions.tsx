import React, { useState, useEffect } from 'react';
import type { SessionInfo, WhoamiResult, SessionHealthResult } from '../types/api';
import * as api from '../hooks/useWails';
import { DataTable, Column } from '../components/shared/DataTable';
import { DetailPanel, DetailRow } from '../components/shared/DetailPanel';
import { Badge, healthBadge } from '../components/shared/Badge';
import { LoadingState, ErrorBanner, Spinner } from '../components/shared/Spinner';
import { formatDate, shortUUID } from '../lib/format';

interface Props {
  onSessionChange: () => void;
}

export function Sessions({ onSessionChange }: Props) {
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [stack, setStack] = useState<SessionInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selected, setSelected] = useState<SessionInfo | null>(null);

  // Whoami state
  const [whoami, setWhoami] = useState<WhoamiResult | null>(null);
  const [whoamiLoading, setWhoamiLoading] = useState(false);

  // Health check state
  const [healthResults, setHealthResults] = useState<SessionHealthResult[] | null>(null);
  const [healthLoading, setHealthLoading] = useState(false);

  // Refresh state
  const [refreshing, setRefreshing] = useState<string | null>(null);

  useEffect(() => { loadData(); }, []);

  const loadData = async () => {
    setLoading(true);
    setError('');
    try {
      const [sess, stk] = await Promise.all([
        api.listSessions(),
        api.peekStack(),
      ]);
      setSessions(sess || []);
      setStack(stk || []);
    } catch (e: any) {
      setError(e?.message || 'Failed to load sessions');
    }
    setLoading(false);
  };

  const handleActivate = async (uuid: string) => {
    try {
      await api.activateSession(uuid);
      await loadData();
      onSessionChange();
    } catch (e: any) {
      alert(e?.message || 'Failed to activate');
    }
  };

  const handlePush = async (uuid: string) => {
    try {
      await api.pushSession(uuid);
      await loadData();
      onSessionChange();
    } catch (e: any) {
      alert(e?.message || 'Failed to push');
    }
  };

  const handlePop = async () => {
    try {
      await api.popSession();
      await loadData();
      onSessionChange();
    } catch (e: any) {
      alert(e?.message || 'Failed to pop');
    }
  };

  const handleExpire = async (uuid: string) => {
    if (!confirm('Expire this session?')) return;
    try {
      await api.expireSession(uuid);
      setSelected(null);
      await loadData();
      onSessionChange();
    } catch (e: any) {
      alert(e?.message || 'Failed to expire');
    }
  };

  const handleWhoami = async (uuid: string) => {
    setWhoami(null);
    setWhoamiLoading(true);
    try {
      const result = await api.sessionWhoami(uuid);
      setWhoami(result);
    } catch (e: any) {
      setWhoami({ arn: '', account_id: '', user_id: '', verified: false, error: typeof e === 'string' ? e : (e?.message || 'Whoami failed') });
    }
    setWhoamiLoading(false);
  };

  const handleHealthCheck = async () => {
    setHealthLoading(true);
    try {
      const results = await api.sessionHealthCheck();
      setHealthResults(results || []);
      await loadData();
    } catch (e: any) {
      alert(typeof e === 'string' ? e : (e?.message || 'Health check failed'));
    }
    setHealthLoading(false);
  };

  const handleRefresh = async (uuid: string) => {
    setRefreshing(uuid);
    try {
      await api.refreshSession(uuid);
      setSelected(null);
      await loadData();
      onSessionChange();
    } catch (e: any) {
      alert(typeof e === 'string' ? e : (e?.message || 'Refresh failed'));
    }
    setRefreshing(null);
  };

  const getHealthDetail = (uuid: string): string | undefined => {
    return healthResults?.find(h => h.uuid === uuid)?.detail;
  };

  const columns: Column<SessionInfo>[] = [
    { key: 'uuid', header: 'UUID', render: s => <span className="font-mono text-xs">{shortUUID(s.uuid)}</span> },
    { key: 'session_name', header: 'Name', render: s => s.session_name || '\u2014' },
    { key: 'region', header: 'Region', render: s => <Badge label={s.region} variant="blue" /> },
    { key: 'health_status', header: 'Health', render: s => (
      <div className="flex items-center gap-1">
        {healthBadge(s.health_status)}
        {getHealthDetail(s.uuid) && (
          <span className="text-xs text-stratus-muted">{getHealthDetail(s.uuid)}</span>
        )}
      </div>
    )},
    { key: 'is_active', header: 'Active', render: s => s.is_active ? <Badge label="active" variant="green" /> : null },
    { key: 'expiry', header: 'Expiry', render: s => <span className="text-xs text-stratus-muted">{s.expiry ? formatDate(s.expiry) : 'No expiry'}</span> },
  ];

  if (loading) return <LoadingState message="Loading sessions..." />;
  if (error) return <ErrorBanner message={error} onRetry={loadData} />;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold">Sessions</h1>
        <div className="flex items-center gap-2">
          <button
            onClick={handleHealthCheck}
            disabled={healthLoading}
            className="btn-ghost text-xs flex items-center gap-1"
          >
            {healthLoading && <Spinner size="sm" />}
            Health Check
          </button>
          {stack.length > 0 && (
            <button onClick={handlePop} className="btn-ghost text-xs">
              Pop Stack
            </button>
          )}
        </div>
      </div>

      {/* Session stack visualization */}
      {stack.length > 0 && (
        <div className="card">
          <h3 className="text-sm font-semibold mb-3">Context Stack</h3>
          <div className="space-y-2">
            {stack.map((s, i) => (
              <div
                key={s.uuid}
                className={`rounded-lg border p-3 flex items-center justify-between transition-colors ${
                  i === 0
                    ? 'border-stratus-accent bg-stratus-accent/5'
                    : 'border-stratus-border/50 opacity-70'
                }`}
              >
                <div className="flex items-center gap-3">
                  <span className="text-xs text-stratus-muted w-6">{i === 0 ? 'TOP' : `#${i}`}</span>
                  <span className="font-mono text-xs">{shortUUID(s.uuid)}</span>
                  <span className="text-sm">{s.session_name || '\u2014'}</span>
                  <Badge label={s.region} variant="blue" />
                  {healthBadge(s.health_status)}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* All sessions table */}
      <div className="card">
        <DataTable
          columns={columns}
          data={sessions}
          onRowClick={setSelected}
          emptyMessage="No sessions created yet"
        />
      </div>

      {/* Detail panel */}
      <DetailPanel
        open={!!selected}
        onClose={() => { setSelected(null); setWhoami(null); }}
        title={selected?.session_name || 'Session Detail'}
      >
        {selected && (
          <>
            <DetailRow label="UUID" value={selected.uuid} mono />
            <DetailRow label="Name" value={selected.session_name} />
            <DetailRow label="Identity UUID" value={selected.identity_uuid} mono />
            <DetailRow label="Region" value={selected.region} />
            <DetailRow label="Health" value={healthBadge(selected.health_status)} />
            <DetailRow label="Active" value={selected.is_active ? 'Yes' : 'No'} />
            <DetailRow label="Expiry" value={selected.expiry ? formatDate(selected.expiry) : 'No expiry'} />

            {/* Whoami result */}
            {whoami && (
              <div className="mt-4 p-3 rounded-lg bg-stratus-bg text-xs space-y-1">
                <div className="font-semibold mb-1">Caller Identity</div>
                {whoami.verified ? (
                  <>
                    <div><span className="text-stratus-muted">ARN:</span> <span className="font-mono">{whoami.arn}</span></div>
                    <div><span className="text-stratus-muted">Account:</span> <span className="font-mono">{whoami.account_id}</span></div>
                    <div><span className="text-stratus-muted">User ID:</span> <span className="font-mono">{whoami.user_id}</span></div>
                    <Badge label="Verified" variant="green" />
                  </>
                ) : (
                  <div className="text-red-400">{whoami.error || 'Verification failed'}</div>
                )}
              </div>
            )}

            <div className="mt-6 pt-4 border-t border-stratus-border flex flex-wrap gap-2">
              <button
                onClick={() => handleWhoami(selected.uuid)}
                disabled={whoamiLoading}
                className="btn-ghost text-xs border border-stratus-border flex items-center gap-1"
              >
                {whoamiLoading && <Spinner size="sm" />}
                Whoami
              </button>
              {!selected.is_active && (
                <button onClick={() => handleActivate(selected.uuid)} className="btn-primary text-xs">
                  Activate
                </button>
              )}
              <button onClick={() => handlePush(selected.uuid)} className="btn-ghost text-xs border border-stratus-border">
                Push to Stack
              </button>
              <button
                onClick={() => handleRefresh(selected.uuid)}
                disabled={refreshing === selected.uuid}
                className="btn-ghost text-xs border border-stratus-border flex items-center gap-1"
              >
                {refreshing === selected.uuid && <Spinner size="sm" />}
                Refresh
              </button>
              <button onClick={() => handleExpire(selected.uuid)} className="btn-danger text-xs">
                Expire
              </button>
            </div>
          </>
        )}
      </DetailPanel>
    </div>
  );
}
