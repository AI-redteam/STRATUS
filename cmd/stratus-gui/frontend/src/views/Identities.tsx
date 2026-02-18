import React, { useState, useEffect } from 'react';
import type { IdentityInfo, SessionInfo } from '../types/api';
import * as api from '../hooks/useWails';
import { DataTable, Column } from '../components/shared/DataTable';
import { DetailPanel, DetailRow } from '../components/shared/DetailPanel';
import { Badge } from '../components/shared/Badge';
import { LoadingState, ErrorBanner } from '../components/shared/Spinner';
import { formatDate, shortUUID, truncateARN, titleCase } from '../lib/format';

export function Identities() {
  const [identities, setIdentities] = useState<IdentityInfo[]>([]);
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selected, setSelected] = useState<IdentityInfo | null>(null);
  const [filter, setFilter] = useState('');

  useEffect(() => { loadData(); }, []);

  const loadData = async () => {
    setLoading(true);
    setError('');
    try {
      const [ids, sess] = await Promise.all([
        api.listIdentities(),
        api.listSessions(),
      ]);
      setIdentities(ids || []);
      setSessions(sess || []);
    } catch (e: any) {
      setError(e?.message || 'Failed to load identities');
    }
    setLoading(false);
  };

  const handleArchive = async (id: IdentityInfo) => {
    if (!confirm(`Archive identity "${id.label || shortUUID(id.uuid)}"?`)) return;
    try {
      await api.archiveIdentity(id.uuid);
      setSelected(null);
      await loadData();
    } catch (e: any) {
      alert(e?.message || 'Failed to archive');
    }
  };

  const filtered = identities.filter(id => {
    if (!filter) return true;
    const f = filter.toLowerCase();
    return id.label.toLowerCase().includes(f) ||
      id.principal_arn.toLowerCase().includes(f) ||
      id.source_type.toLowerCase().includes(f) ||
      id.account_id.includes(f);
  });

  const linkedSessions = selected
    ? sessions.filter(s => s.identity_uuid === selected.uuid)
    : [];

  const columns: Column<IdentityInfo>[] = [
    { key: 'label', header: 'Label', render: id => <span className="font-medium">{id.label || shortUUID(id.uuid)}</span> },
    { key: 'source_type', header: 'Source', render: id => <Badge label={titleCase(id.source_type)} variant="blue" /> },
    { key: 'principal_type', header: 'Type', render: id => <span className="text-xs text-stratus-muted">{titleCase(id.principal_type)}</span> },
    { key: 'account_id', header: 'Account', render: id => <span className="font-mono text-xs">{id.account_id}</span> },
    { key: 'principal_arn', header: 'ARN', render: id => <span className="font-mono text-xs">{truncateARN(id.principal_arn)}</span> },
    { key: 'acquired_at', header: 'Acquired', render: id => <span className="text-xs text-stratus-muted">{formatDate(id.acquired_at)}</span> },
  ];

  if (loading) return <LoadingState message="Loading identities..." />;
  if (error) return <ErrorBanner message={error} onRetry={loadData} />;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold">Identities</h1>
        <input
          type="text"
          className="input-field w-64"
          placeholder="Filter identities..."
          value={filter}
          onChange={e => setFilter(e.target.value)}
        />
      </div>

      <div className="card">
        <DataTable
          columns={columns}
          data={filtered}
          onRowClick={setSelected}
          emptyMessage="No identities imported yet"
        />
      </div>

      <DetailPanel
        open={!!selected}
        onClose={() => setSelected(null)}
        title={selected?.label || 'Identity Detail'}
      >
        {selected && (
          <>
            <DetailRow label="UUID" value={selected.uuid} mono />
            <DetailRow label="Label" value={selected.label} />
            <DetailRow label="Source Type" value={titleCase(selected.source_type)} />
            <DetailRow label="Principal Type" value={titleCase(selected.principal_type)} />
            <DetailRow label="Principal ARN" value={selected.principal_arn} mono />
            <DetailRow label="Account ID" value={selected.account_id} mono />
            <DetailRow label="Acquired" value={formatDate(selected.acquired_at)} />

            {linkedSessions.length > 0 && (
              <div className="mt-6">
                <h3 className="text-sm font-semibold mb-2">Linked Sessions ({linkedSessions.length})</h3>
                <div className="space-y-2">
                  {linkedSessions.map(s => (
                    <div key={s.uuid} className="bg-stratus-bg rounded p-3 text-xs space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="font-mono">{shortUUID(s.uuid)}</span>
                        <Badge label={s.health_status} variant={s.health_status === 'healthy' ? 'green' : 'yellow'} />
                      </div>
                      <div className="text-stratus-muted">{s.session_name} &middot; {s.region}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="mt-6 pt-4 border-t border-stratus-border">
              <button
                onClick={() => handleArchive(selected)}
                className="btn-danger text-xs"
              >
                Archive Identity
              </button>
            </div>
          </>
        )}
      </DetailPanel>
    </div>
  );
}
