import React, { useState, useEffect } from 'react';
import type { IdentityInfo, SessionInfo } from '../types/api';
import * as api from '../hooks/useWails';
import { DataTable, Column } from '../components/shared/DataTable';
import { DetailPanel, DetailRow } from '../components/shared/DetailPanel';
import { Badge } from '../components/shared/Badge';
import { LoadingState, ErrorBanner, Spinner } from '../components/shared/Spinner';
import { formatDate, shortUUID, truncateARN, titleCase } from '../lib/format';

type ImportType = 'iam-key' | 'sts-session' | 'assume-role' | 'imds-capture' | 'web-identity' | 'cred-process';

export function Identities() {
  const [identities, setIdentities] = useState<IdentityInfo[]>([]);
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selected, setSelected] = useState<IdentityInfo | null>(null);
  const [filter, setFilter] = useState('');

  // Import dialog state
  const [showImport, setShowImport] = useState(false);
  const [importType, setImportType] = useState<ImportType>('iam-key');
  const [importAccessKey, setImportAccessKey] = useState('');
  const [importSecretKey, setImportSecretKey] = useState('');
  const [importSessionToken, setImportSessionToken] = useState('');
  const [importLabel, setImportLabel] = useState('');
  const [importRegion, setImportRegion] = useState('us-east-1');
  const [importRoleArn, setImportRoleArn] = useState('');
  const [importExternalId, setImportExternalId] = useState('');
  const [importRawToken, setImportRawToken] = useState('');
  const [importCommand, setImportCommand] = useState('');
  const [importRoleName, setImportRoleName] = useState('');
  const [importExpiry, setImportExpiry] = useState('');
  const [importing, setImporting] = useState(false);
  const [importError, setImportError] = useState('');

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

  const resetImportForm = () => {
    setImportAccessKey('');
    setImportSecretKey('');
    setImportSessionToken('');
    setImportLabel('');
    setImportRegion('us-east-1');
    setImportRoleArn('');
    setImportExternalId('');
    setImportRawToken('');
    setImportCommand('');
    setImportRoleName('');
    setImportExpiry('');
    setImportError('');
    setImporting(false);
  };

  const handleImport = async () => {
    setImportError('');

    // Validation per type
    if (importType === 'iam-key' && (!importAccessKey || !importSecretKey)) {
      setImportError('Access key and secret key are required');
      return;
    }
    if (importType === 'sts-session' && (!importAccessKey || !importSecretKey || !importSessionToken)) {
      setImportError('Access key, secret key, and session token are required');
      return;
    }
    if (importType === 'assume-role' && !importRoleArn) {
      setImportError('Role ARN is required');
      return;
    }
    if (importType === 'imds-capture' && (!importAccessKey || !importSecretKey || !importSessionToken)) {
      setImportError('Access key, secret key, and session token are required');
      return;
    }
    if (importType === 'web-identity' && (!importRoleArn || !importRawToken)) {
      setImportError('Role ARN and token are required');
      return;
    }
    if (importType === 'cred-process' && !importCommand) {
      setImportError('Command is required');
      return;
    }

    setImporting(true);
    try {
      if (importType === 'iam-key') {
        await api.importIAMKey({
          access_key: importAccessKey,
          secret_key: importSecretKey,
          label: importLabel,
          region: importRegion,
        });
      } else if (importType === 'sts-session') {
        await api.importSTSSession({
          access_key: importAccessKey,
          secret_key: importSecretKey,
          session_token: importSessionToken,
          label: importLabel,
          region: importRegion,
        });
      } else if (importType === 'assume-role') {
        await api.importAssumeRoleIdentity({
          role_arn: importRoleArn,
          external_id: importExternalId || undefined,
          label: importLabel,
        });
      } else if (importType === 'imds-capture') {
        await api.importIMDS({
          access_key: importAccessKey,
          secret_key: importSecretKey,
          session_token: importSessionToken,
          expiry: importExpiry || undefined,
          role_name: importRoleName || undefined,
          label: importLabel,
          region: importRegion,
        });
      } else if (importType === 'web-identity') {
        await api.importWebIdentity({
          role_arn: importRoleArn,
          raw_token: importRawToken,
          label: importLabel,
        });
      } else if (importType === 'cred-process') {
        await api.importCredProcess({
          command: importCommand,
          access_key: importAccessKey || undefined,
          secret_key: importSecretKey || undefined,
          session_token: importSessionToken || undefined,
          expiry: importExpiry || undefined,
          label: importLabel,
          region: importRegion,
        });
      }
      setShowImport(false);
      resetImportForm();
      await loadData();
    } catch (e: any) {
      const msg = typeof e === 'string' ? e : (e?.message || 'Import failed');
      setImportError(msg);
    }
    setImporting(false);
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
        <div className="flex items-center gap-2">
          <input
            type="text"
            className="input-field w-64"
            placeholder="Filter identities..."
            value={filter}
            onChange={e => setFilter(e.target.value)}
          />
          <button onClick={() => setShowImport(true)} className="btn-primary text-sm">
            + Import
          </button>
        </div>
      </div>

      <div className="card">
        <DataTable
          columns={columns}
          data={filtered}
          onRowClick={setSelected}
          emptyMessage="No identities imported yet"
        />
      </div>

      {/* Identity detail panel */}
      <DetailPanel
        open={!!selected && !showImport}
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

      {/* Import identity panel */}
      <DetailPanel
        open={showImport}
        onClose={() => { setShowImport(false); resetImportForm(); }}
        title="Import Identity"
      >
        <div className="space-y-4">
          {/* Type selector */}
          <div>
            <label className="block text-xs text-stratus-muted uppercase mb-2">Credential Type</label>
            <div className="grid grid-cols-3 gap-2">
              {([
                ['iam-key', 'IAM Key'],
                ['sts-session', 'STS Session'],
                ['assume-role', 'Assume Role'],
                ['imds-capture', 'IMDS Capture'],
                ['web-identity', 'Web Identity'],
                ['cred-process', 'Cred Process'],
              ] as [ImportType, string][]).map(([type, label]) => (
                <button
                  key={type}
                  onClick={() => setImportType(type)}
                  className={`px-3 py-2 rounded border text-xs transition-colors ${
                    importType === type
                      ? 'border-stratus-accent bg-stratus-accent/10 text-stratus-accent'
                      : 'border-stratus-border text-stratus-muted hover:border-stratus-accent/50'
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          {/* Label — always shown */}
          <div>
            <label className="block text-xs text-stratus-muted uppercase mb-1">Label</label>
            <input
              type="text"
              className="input-field"
              placeholder="e.g. ci-readonly, compromised-lambda"
              value={importLabel}
              onChange={e => setImportLabel(e.target.value)}
            />
          </div>

          {/* --- IAM Key / STS / IMDS / Cred Process fields --- */}
          {(importType === 'iam-key' || importType === 'sts-session' || importType === 'imds-capture' || importType === 'cred-process') && (
            <>
              <div>
                <label className="block text-xs text-stratus-muted uppercase mb-1">
                  Access Key ID {importType !== 'cred-process' && <span className="text-red-400">*</span>}
                </label>
                <input
                  type="text"
                  className="input-field font-mono"
                  placeholder="AKIAXXXXXXXXXXXXXXXX"
                  value={importAccessKey}
                  onChange={e => setImportAccessKey(e.target.value)}
                />
              </div>
              <div>
                <label className="block text-xs text-stratus-muted uppercase mb-1">
                  Secret Access Key {importType !== 'cred-process' && <span className="text-red-400">*</span>}
                </label>
                <input
                  type="password"
                  className="input-field font-mono"
                  placeholder="Enter secret key..."
                  value={importSecretKey}
                  onChange={e => setImportSecretKey(e.target.value)}
                />
              </div>
            </>
          )}

          {/* Session Token (STS, IMDS, Cred Process) */}
          {(importType === 'sts-session' || importType === 'imds-capture' || importType === 'cred-process') && (
            <div>
              <label className="block text-xs text-stratus-muted uppercase mb-1">
                Session Token {importType !== 'cred-process' && <span className="text-red-400">*</span>}
              </label>
              <textarea
                className="input-field font-mono text-xs h-24 resize-none"
                placeholder="Paste session token..."
                value={importSessionToken}
                onChange={e => setImportSessionToken(e.target.value)}
              />
            </div>
          )}

          {/* Expiry (STS, IMDS, Cred Process) */}
          {(importType === 'sts-session' || importType === 'imds-capture' || importType === 'cred-process') && (
            <div>
              <label className="block text-xs text-stratus-muted uppercase mb-1">Expiry (RFC3339)</label>
              <input
                type="text"
                className="input-field font-mono text-xs"
                placeholder="2024-01-01T00:00:00Z"
                value={importExpiry}
                onChange={e => setImportExpiry(e.target.value)}
              />
            </div>
          )}

          {/* IMDS-specific: Role Name */}
          {importType === 'imds-capture' && (
            <div>
              <label className="block text-xs text-stratus-muted uppercase mb-1">EC2 Role Name</label>
              <input
                type="text"
                className="input-field"
                placeholder="e.g. my-ec2-role"
                value={importRoleName}
                onChange={e => setImportRoleName(e.target.value)}
              />
            </div>
          )}

          {/* Role ARN (Assume Role, Web Identity) */}
          {(importType === 'assume-role' || importType === 'web-identity') && (
            <div>
              <label className="block text-xs text-stratus-muted uppercase mb-1">
                Role ARN <span className="text-red-400">*</span>
              </label>
              <input
                type="text"
                className="input-field font-mono text-xs"
                placeholder="arn:aws:iam::123456789012:role/RoleName"
                value={importRoleArn}
                onChange={e => setImportRoleArn(e.target.value)}
              />
            </div>
          )}

          {/* External ID (Assume Role) */}
          {importType === 'assume-role' && (
            <div>
              <label className="block text-xs text-stratus-muted uppercase mb-1">External ID</label>
              <input
                type="text"
                className="input-field font-mono text-xs"
                placeholder="Optional external ID"
                value={importExternalId}
                onChange={e => setImportExternalId(e.target.value)}
              />
            </div>
          )}

          {/* Raw Token (Web Identity) */}
          {importType === 'web-identity' && (
            <div>
              <label className="block text-xs text-stratus-muted uppercase mb-1">
                OIDC/JWT Token <span className="text-red-400">*</span>
              </label>
              <textarea
                className="input-field font-mono text-xs h-24 resize-none"
                placeholder="Paste OIDC/JWT token..."
                value={importRawToken}
                onChange={e => setImportRawToken(e.target.value)}
              />
            </div>
          )}

          {/* Command (Cred Process) */}
          {importType === 'cred-process' && (
            <div>
              <label className="block text-xs text-stratus-muted uppercase mb-1">
                Command <span className="text-red-400">*</span>
              </label>
              <input
                type="text"
                className="input-field font-mono text-xs"
                placeholder="e.g. /usr/local/bin/aws-cred-helper"
                value={importCommand}
                onChange={e => setImportCommand(e.target.value)}
              />
              <p className="text-xs text-stratus-muted mt-1">
                Paste pre-captured credentials above, or store command reference only.
              </p>
            </div>
          )}

          {/* Region (not shown for assume-role, web-identity) */}
          {importType !== 'assume-role' && importType !== 'web-identity' && (
            <div>
              <label className="block text-xs text-stratus-muted uppercase mb-1">Region</label>
              <input
                type="text"
                className="input-field"
                value={importRegion}
                onChange={e => setImportRegion(e.target.value)}
              />
            </div>
          )}

          {importError && <ErrorBanner message={importError} />}

          <button
            onClick={handleImport}
            disabled={importing}
            className="btn-primary w-full flex items-center justify-center gap-2"
          >
            {importing && <Spinner size="sm" />}
            {importing ? 'Importing...' : 'Import Identity'}
          </button>
        </div>
      </DetailPanel>
    </div>
  );
}
