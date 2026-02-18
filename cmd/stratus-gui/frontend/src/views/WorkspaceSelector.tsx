import React, { useState, useEffect } from 'react';
import type { WorkspaceEntry } from '../types/api';
import * as api from '../hooks/useWails';
import { Spinner, ErrorBanner } from '../components/shared/Spinner';

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

  useEffect(() => {
    api.listWorkspaces()
      .then(ws => {
        setWorkspaces(ws || []);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

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
          <div className="text-center py-8 text-stratus-muted text-sm">
            No workspaces found.<br />
            Create one with the CLI first:<br />
            <code className="text-xs mt-2 block text-stratus-accent">stratus workspace new</code>
          </div>
        ) : (
          <>
            <div>
              <label className="block text-xs text-stratus-muted uppercase mb-2">Select Workspace</label>
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
