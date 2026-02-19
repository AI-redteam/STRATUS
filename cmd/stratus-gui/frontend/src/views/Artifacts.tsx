import React, { useState, useEffect } from 'react';
import type { ArtifactInfo, ArtifactContent, VerifyArtifactsResult } from '../types/api';
import * as api from '../hooks/useWails';
import { DataTable, Column } from '../components/shared/DataTable';
import { DetailPanel, DetailRow } from '../components/shared/DetailPanel';
import { Badge } from '../components/shared/Badge';
import { LoadingState, ErrorBanner, Spinner } from '../components/shared/Spinner';
import { formatDate, shortUUID } from '../lib/format';

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function Artifacts() {
  const [artifacts, setArtifacts] = useState<ArtifactInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selected, setSelected] = useState<ArtifactInfo | null>(null);
  const [content, setContent] = useState<ArtifactContent | null>(null);
  const [contentLoading, setContentLoading] = useState(false);
  const [typeFilter, setTypeFilter] = useState('');
  const [verifyResult, setVerifyResult] = useState<VerifyArtifactsResult | null>(null);
  const [verifying, setVerifying] = useState(false);

  useEffect(() => { loadData(); }, []);

  const loadData = async () => {
    setLoading(true);
    setError('');
    try {
      const arts = await api.listArtifacts('', typeFilter);
      setArtifacts(arts || []);
    } catch (e: any) {
      setError(typeof e === 'string' ? e : (e?.message || 'Failed to load artifacts'));
    }
    setLoading(false);
  };

  useEffect(() => { loadData(); }, [typeFilter]);

  const handleSelect = async (art: ArtifactInfo) => {
    setSelected(art);
    setContent(null);
    setContentLoading(true);
    try {
      const c = await api.getArtifact(art.uuid);
      setContent(c);
    } catch {
      setContent(null);
    }
    setContentLoading(false);
  };

  const handleVerify = async () => {
    setVerifying(true);
    try {
      const result = await api.verifyArtifacts();
      setVerifyResult(result);
    } catch (e: any) {
      alert(typeof e === 'string' ? e : (e?.message || 'Verification failed'));
    }
    setVerifying(false);
  };

  const artifactTypes = Array.from(new Set(artifacts.map(a => a.type)));

  const columns: Column<ArtifactInfo>[] = [
    { key: 'uuid', header: 'UUID', render: a => <span className="font-mono text-xs">{shortUUID(a.uuid)}</span> },
    { key: 'label', header: 'Label', render: a => <span className="text-sm">{a.label || '\u2014'}</span> },
    { key: 'type', header: 'Type', render: a => <Badge label={a.type} variant="blue" /> },
    { key: 'size_bytes', header: 'Size', render: a => <span className="text-xs text-stratus-muted">{formatBytes(a.size_bytes)}</span> },
    { key: 'sha256', header: 'SHA-256', render: a => <span className="font-mono text-xs text-stratus-muted">{a.sha256.slice(0, 12)}...</span> },
    { key: 'created_at', header: 'Created', render: a => <span className="text-xs text-stratus-muted">{formatDate(a.created_at)}</span> },
  ];

  if (loading) return <LoadingState message="Loading artifacts..." />;
  if (error) return <ErrorBanner message={error} onRetry={loadData} />;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-bold">Artifacts</h1>
          <Badge label={`${artifacts.length} total`} variant="purple" />
        </div>
        <div className="flex items-center gap-2">
          <select
            className="input-field text-xs w-40"
            value={typeFilter}
            onChange={e => setTypeFilter(e.target.value)}
          >
            <option value="">All types</option>
            {artifactTypes.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
          <button
            onClick={handleVerify}
            disabled={verifying}
            className="btn-ghost text-xs flex items-center gap-1"
          >
            {verifying && <Spinner size="sm" />}
            Verify All
          </button>
        </div>
      </div>

      {verifyResult && (
        <div className={`card text-xs flex items-center gap-3 ${verifyResult.all_valid ? 'border-green-500/30' : 'border-red-500/30'}`}>
          <Badge label={verifyResult.all_valid ? 'All Valid' : 'Corruption Detected'} variant={verifyResult.all_valid ? 'green' : 'red'} />
          <span>{verifyResult.valid}/{verifyResult.total} valid</span>
          {verifyResult.corrupt > 0 && <span className="text-red-400">{verifyResult.corrupt} corrupt</span>}
        </div>
      )}

      <div className="card">
        <DataTable
          columns={columns}
          data={artifacts}
          onRowClick={handleSelect}
          emptyMessage="No artifacts stored yet. Run modules to generate artifacts."
        />
      </div>

      <DetailPanel
        open={!!selected}
        onClose={() => { setSelected(null); setContent(null); }}
        title={selected?.label || 'Artifact Detail'}
      >
        {selected && (
          <>
            <DetailRow label="UUID" value={selected.uuid} mono />
            <DetailRow label="Label" value={selected.label} />
            <DetailRow label="Type" value={selected.type} />
            <DetailRow label="Size" value={formatBytes(selected.size_bytes)} />
            <DetailRow label="SHA-256" value={selected.sha256} mono />
            {selected.run_uuid && <DetailRow label="Run UUID" value={selected.run_uuid} mono />}
            {selected.session_uuid && <DetailRow label="Session UUID" value={selected.session_uuid} mono />}
            <DetailRow label="Created" value={formatDate(selected.created_at)} />

            {/* Content preview */}
            <div className="mt-4 pt-4 border-t border-stratus-border">
              <h4 className="text-xs text-stratus-muted uppercase mb-2">Content Preview</h4>
              {contentLoading ? (
                <div className="flex justify-center py-4"><Spinner /></div>
              ) : content ? (
                <pre className="bg-stratus-bg rounded p-3 text-xs font-mono overflow-auto max-h-64 whitespace-pre-wrap break-all">
                  {content.content}
                </pre>
              ) : (
                <span className="text-xs text-stratus-muted">Unable to load content</span>
              )}
            </div>
          </>
        )}
      </DetailPanel>
    </div>
  );
}
