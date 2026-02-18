import React, { useState, useEffect } from 'react';
import type { AuditEntry } from '../types/api';
import * as api from '../hooks/useWails';
import { DataTable, Column } from '../components/shared/DataTable';
import { Badge, eventTypeBadge } from '../components/shared/Badge';
import { LoadingState, ErrorBanner, Spinner } from '../components/shared/Spinner';
import { formatDate, shortUUID } from '../lib/format';

const PAGE_SIZE = 50;

export function Audit() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [chainValid, setChainValid] = useState<boolean | null>(null);
  const [chainCount, setChainCount] = useState(0);
  const [verifying, setVerifying] = useState(false);
  const [eventFilter, setEventFilter] = useState('');
  const [offset, setOffset] = useState(0);
  const [expandedId, setExpandedId] = useState<number | null>(null);

  useEffect(() => { loadData(); }, [eventFilter, offset]);

  const loadData = async () => {
    setLoading(true);
    setError('');
    try {
      const [events, chain] = await Promise.all([
        api.listAuditEvents(PAGE_SIZE, offset, eventFilter),
        chainValid === null ? api.verifyAuditChain() : Promise.resolve(null),
      ]);
      setEntries(events || []);
      if (chain) {
        setChainValid(chain.valid);
        setChainCount(chain.count);
      }
    } catch (e: any) {
      setError(e?.message || 'Failed to load audit log');
    }
    setLoading(false);
  };

  const handleVerify = async () => {
    setVerifying(true);
    try {
      const result = await api.verifyAuditChain();
      setChainValid(result.valid);
      setChainCount(result.count);
    } catch (e: any) {
      alert(e?.message || 'Verification failed');
    }
    setVerifying(false);
  };

  const eventTypes = [
    'api_call', 'session_activated', 'identity_imported', 'scope_violation',
    'module_run', 'workspace_created', 'session_expired',
  ];

  const columns: Column<AuditEntry>[] = [
    { key: 'id', header: '#', render: e => <span className="text-xs text-stratus-muted">{e.id}</span>, width: '60px' },
    { key: 'timestamp', header: 'Time', render: e => <span className="text-xs">{formatDate(e.timestamp)}</span> },
    { key: 'event_type', header: 'Event', render: e => eventTypeBadge(e.event_type) },
    { key: 'operator', header: 'Operator', render: e => <span className="text-xs font-mono">{e.operator}</span> },
    { key: 'session_uuid', header: 'Session', render: e => (
      <span className="text-xs font-mono text-stratus-muted">
        {e.session_uuid ? shortUUID(e.session_uuid) : '—'}
      </span>
    )},
    { key: 'detail', header: '', render: e => (
      <button
        className="text-xs text-stratus-accent hover:underline"
        onClick={(ev) => { ev.stopPropagation(); setExpandedId(expandedId === e.id ? null : e.id); }}
      >
        {expandedId === e.id ? 'Hide' : 'Detail'}
      </button>
    ), sortable: false, width: '60px' },
  ];

  if (loading && entries.length === 0) return <LoadingState message="Loading audit log..." />;
  if (error) return <ErrorBanner message={error} onRetry={loadData} />;

  return (
    <div className="space-y-4">
      {/* Chain status banner */}
      <div className={`rounded-lg p-4 flex items-center justify-between ${
        chainValid === null ? 'bg-stratus-surface border border-stratus-border' :
        chainValid ? 'bg-emerald-900/20 border border-emerald-700' : 'bg-red-900/20 border border-red-700'
      }`}>
        <div className="flex items-center gap-3">
          {chainValid === true && (
            <svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          )}
          {chainValid === false && (
            <svg className="w-5 h-5 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          )}
          <div>
            <span className="text-sm font-medium">
              {chainValid === null ? 'Audit Chain' : chainValid ? 'Audit Chain Verified' : 'Audit Chain BROKEN'}
            </span>
            {chainCount > 0 && (
              <span className="text-xs text-stratus-muted ml-2">{chainCount} records</span>
            )}
          </div>
        </div>
        <button
          onClick={handleVerify}
          disabled={verifying}
          className="btn-ghost text-xs flex items-center gap-2"
        >
          {verifying && <Spinner size="sm" />}
          Verify Chain
        </button>
      </div>

      {/* Filters */}
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold">Audit Log</h1>
        <select
          className="input-field w-48"
          value={eventFilter}
          onChange={e => { setEventFilter(e.target.value); setOffset(0); }}
        >
          <option value="">All Events</option>
          {eventTypes.map(t => <option key={t} value={t}>{t.replace('_', ' ')}</option>)}
        </select>
      </div>

      {/* Table */}
      <div className="card">
        <DataTable
          columns={columns}
          data={entries}
          keyField="id"
          emptyMessage="No audit events"
        />

        {/* Expanded detail row */}
        {expandedId !== null && entries.find(e => e.id === expandedId) && (
          <div className="mx-4 mb-4 bg-stratus-bg rounded-lg p-4">
            <pre className="text-xs overflow-auto max-h-64 whitespace-pre-wrap">
              {(() => {
                const entry = entries.find(e => e.id === expandedId)!;
                try {
                  return JSON.stringify(JSON.parse(entry.detail), null, 2);
                } catch {
                  return entry.detail;
                }
              })()}
            </pre>
            <div className="mt-2 text-xs text-stratus-muted font-mono">
              Hash: {entries.find(e => e.id === expandedId)?.record_hash.slice(0, 16)}...
            </div>
          </div>
        )}

        {/* Pagination */}
        <div className="flex items-center justify-between px-4 py-3 border-t border-stratus-border">
          <button
            onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
            disabled={offset === 0}
            className="btn-ghost text-xs"
          >
            Previous
          </button>
          <span className="text-xs text-stratus-muted">
            Showing {offset + 1} - {offset + entries.length}
          </span>
          <button
            onClick={() => setOffset(offset + PAGE_SIZE)}
            disabled={entries.length < PAGE_SIZE}
            className="btn-ghost text-xs"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
}
