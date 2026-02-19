import React, { useState, useEffect } from 'react';
import type { WorkspaceEntry } from '../types/api';
import * as api from '../hooks/useWails';
import { Spinner, ErrorBanner } from '../components/shared/Spinner';

const AWS_REGIONS = [
  'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
  'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-north-1', 'eu-south-1',
  'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 'ap-south-1',
  'sa-east-1', 'ca-central-1', 'me-south-1', 'af-south-1',
];

interface Props {
  onOpen: (path: string, passphrase: string) => Promise<void>;
}

export function WorkspaceSelector({ onOpen }: Props) {
  const [workspaces, setWorkspaces] = useState<WorkspaceEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<WorkspaceEntry | null>(null);
  const [passphrase, setPassphrase] = useState('');
  const [error, setError] = useState('');
  const [opening, setOpening] = useState(false);

  // Create workspace dialog state
  const [showCreate, setShowCreate] = useState(false);
  const [createName, setCreateName] = useState('');
  const [createDesc, setCreateDesc] = useState('');
  const [createPass, setCreatePass] = useState('');
  const [createPassConfirm, setCreatePassConfirm] = useState('');
  const [createAccounts, setCreateAccounts] = useState('');
  const [createRegions, setCreateRegions] = useState<string[]>([]);
  const [createPartition, setCreatePartition] = useState('aws');
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState('');

  const refreshWorkspaces = async () => {
    setLoading(true);
    try {
      const ws = await api.listWorkspaces();
      setWorkspaces(ws || []);
    } catch {}
    setLoading(false);
  };

  useEffect(() => { refreshWorkspaces(); }, []);

  const handleOpen = async () => {
    if (!selected || !passphrase) return;
    setError('');
    setOpening(true);
    try {
      await onOpen(selected.path, passphrase);
    } catch (e: any) {
      setError(e?.message || 'Failed to open workspace');
      setOpening(false);
    }
  };

  const resetCreateForm = () => {
    setCreateName('');
    setCreateDesc('');
    setCreatePass('');
    setCreatePassConfirm('');
    setCreateAccounts('');
    setCreateRegions([]);
    setCreatePartition('aws');
    setCreateError('');
    setCreating(false);
  };

  const handleCreate = async () => {
    setCreateError('');
    if (!createName.trim()) {
      setCreateError('Workspace name is required');
      return;
    }
    if (!createPass) {
      setCreateError('Passphrase is required');
      return;
    }
    if (createPass !== createPassConfirm) {
      setCreateError('Passphrases do not match');
      return;
    }
    if (createPass.length < 8) {
      setCreateError('Passphrase must be at least 8 characters');
      return;
    }

    setCreating(true);
    try {
      const accounts = createAccounts.split(',').map(s => s.trim()).filter(Boolean);
      const result = await api.createWorkspace({
        name: createName.trim(),
        description: createDesc.trim(),
        passphrase: createPass,
        accounts,
        regions: createRegions,
        partition: createPartition,
      });
      // Workspace is auto-opened by the backend — trigger parent callback
      // by using the returned path/passphrase combo
      setShowCreate(false);
      resetCreateForm();
      // The workspace is already opened on the backend. Reload to enter main UI.
      await onOpen(result.path, createPass);
    } catch (e: any) {
      const msg = typeof e === 'string' ? e : (e?.message || 'Failed to create workspace');
      setCreateError(msg);
      setCreating(false);
    }
  };

  const toggleRegion = (region: string) => {
    setCreateRegions(prev =>
      prev.includes(region) ? prev.filter(r => r !== region) : [...prev, region]
    );
  };

  if (showCreate) {
    return (
      <div className="min-h-screen bg-stratus-bg flex items-center justify-center">
        <div className="w-[520px] card space-y-5 max-h-[90vh] overflow-y-auto">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-bold">Create Workspace</h2>
            <button
              onClick={() => { setShowCreate(false); resetCreateForm(); }}
              className="text-stratus-muted hover:text-stratus-text text-lg"
            >&times;</button>
          </div>

          {createError && <ErrorBanner message={createError} />}

          <div>
            <label className="block text-xs text-stratus-muted uppercase mb-1">
              Name <span className="text-red-400">*</span>
            </label>
            <input
              type="text"
              className="input-field"
              placeholder="e.g. acme-pentest-2026"
              value={createName}
              onChange={e => setCreateName(e.target.value)}
            />
          </div>

          <div>
            <label className="block text-xs text-stratus-muted uppercase mb-1">Description</label>
            <input
              type="text"
              className="input-field"
              placeholder="Engagement description (optional)"
              value={createDesc}
              onChange={e => setCreateDesc(e.target.value)}
            />
          </div>

          <div>
            <label className="block text-xs text-stratus-muted uppercase mb-1">
              Vault Passphrase <span className="text-red-400">*</span>
            </label>
            <input
              type="password"
              className="input-field"
              placeholder="Minimum 8 characters"
              value={createPass}
              onChange={e => setCreatePass(e.target.value)}
            />
          </div>

          <div>
            <label className="block text-xs text-stratus-muted uppercase mb-1">
              Confirm Passphrase <span className="text-red-400">*</span>
            </label>
            <input
              type="password"
              className="input-field"
              placeholder="Re-enter passphrase"
              value={createPassConfirm}
              onChange={e => setCreatePassConfirm(e.target.value)}
            />
          </div>

          <hr className="border-stratus-border" />

          <div>
            <label className="block text-xs text-stratus-muted uppercase mb-1">
              Scope: AWS Account IDs
            </label>
            <input
              type="text"
              className="input-field font-mono"
              placeholder="123456789012, 210987654321"
              value={createAccounts}
              onChange={e => setCreateAccounts(e.target.value)}
            />
            <p className="text-xs text-stratus-muted mt-1">Comma-separated. Leave blank for unrestricted.</p>
          </div>

          <div>
            <label className="block text-xs text-stratus-muted uppercase mb-2">
              Scope: AWS Regions
            </label>
            <div className="grid grid-cols-4 gap-1.5 max-h-32 overflow-y-auto">
              {AWS_REGIONS.map(r => (
                <button
                  key={r}
                  onClick={() => toggleRegion(r)}
                  className={`text-xs px-2 py-1 rounded border transition-colors ${
                    createRegions.includes(r)
                      ? 'border-stratus-accent bg-stratus-accent/10 text-stratus-accent'
                      : 'border-stratus-border text-stratus-muted hover:border-stratus-accent/50'
                  }`}
                >{r}</button>
              ))}
            </div>
            <p className="text-xs text-stratus-muted mt-1">Click to toggle. None selected = unrestricted.</p>
          </div>

          <div>
            <label className="block text-xs text-stratus-muted uppercase mb-1">Partition</label>
            <select
              className="input-field"
              value={createPartition}
              onChange={e => setCreatePartition(e.target.value)}
            >
              <option value="aws">aws (Standard)</option>
              <option value="aws-cn">aws-cn (China)</option>
              <option value="aws-us-gov">aws-us-gov (GovCloud)</option>
            </select>
          </div>

          <button
            onClick={handleCreate}
            disabled={creating}
            className="btn-primary w-full flex items-center justify-center gap-2"
          >
            {creating && <Spinner size="sm" />}
            {creating ? 'Creating...' : 'Create Workspace'}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-stratus-bg flex items-center justify-center">
      <div className="w-[440px] card space-y-6">
        {/* Logo */}
        <div className="text-center space-y-2">
          <div className="w-16 h-16 mx-auto rounded-xl bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-white font-bold text-2xl">
            S
          </div>
          <h1 className="text-2xl font-bold tracking-wider">STRATUS</h1>
          <p className="text-sm text-stratus-muted">AWS Adversary Emulation Framework</p>
        </div>

        {error && <ErrorBanner message={error} />}

        {loading ? (
          <div className="py-8 flex justify-center"><Spinner /></div>
        ) : workspaces.length === 0 ? (
          <div className="text-center py-8 space-y-4">
            <p className="text-stratus-muted text-sm">No workspaces found.</p>
            <button onClick={() => setShowCreate(true)} className="btn-primary">
              Create Workspace
            </button>
            <button onClick={refreshWorkspaces} className="btn-ghost text-xs block mx-auto mt-2">
              Refresh
            </button>
          </div>
        ) : (
          <>
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="text-xs text-stratus-muted uppercase">Select Workspace</label>
                <div className="flex items-center gap-3">
                  <button onClick={() => setShowCreate(true)} className="text-xs text-stratus-accent hover:underline">
                    + New
                  </button>
                  <button onClick={refreshWorkspaces} className="text-xs text-stratus-accent hover:underline">
                    Refresh
                  </button>
                </div>
              </div>
              <div className="space-y-2 max-h-48 overflow-y-auto">
                {workspaces.map(ws => (
                  <button
                    key={ws.uuid}
                    onClick={() => setSelected(ws)}
                    className={`w-full text-left px-4 py-3 rounded-lg border transition-colors ${
                      selected?.uuid === ws.uuid
                        ? 'border-stratus-accent bg-stratus-accent/10'
                        : 'border-stratus-border hover:border-stratus-accent/50'
                    }`}
                  >
                    <div className="font-medium text-sm">{ws.name}</div>
                    <div className="text-xs text-stratus-muted font-mono mt-0.5">{ws.uuid.slice(0, 8)}</div>
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label className="block text-xs text-stratus-muted uppercase mb-2">Vault Passphrase</label>
              <input
                type="password"
                className="input-field"
                placeholder="Enter passphrase to unlock vault..."
                value={passphrase}
                onChange={e => setPassphrase(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleOpen()}
              />
            </div>

            <button
              onClick={handleOpen}
              disabled={!selected || !passphrase || opening}
              className="btn-primary w-full flex items-center justify-center gap-2"
            >
              {opening && <Spinner size="sm" />}
              {opening ? 'Unlocking...' : 'Open Workspace'}
            </button>
          </>
        )}
      </div>
    </div>
  );
}
