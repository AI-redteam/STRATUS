import React from 'react';
import type { WorkspaceInfo, SessionInfo } from '../../types/api';
import { Badge, healthBadge } from '../shared/Badge';
import { shortUUID } from '../../lib/format';

interface HeaderProps {
  workspace: WorkspaceInfo | null;
  activeSession: SessionInfo | null;
  onCloseWorkspace: () => void;
}

export function Header({ workspace, activeSession, onCloseWorkspace }: HeaderProps) {
  return (
    <header className="h-12 bg-stratus-surface border-b border-stratus-border flex items-center justify-between px-5 shrink-0 wails-drag">
      <div className="flex items-center gap-4">
        {workspace && (
          <>
            <span className="text-sm font-medium">{workspace.name}</span>
            <span className="text-xs text-stratus-muted font-mono">{shortUUID(workspace.uuid)}</span>
          </>
        )}
      </div>

      <div className="flex items-center gap-4" style={{ WebkitAppRegion: 'no-drag' } as React.CSSProperties}>
        {activeSession && (
          <div className="flex items-center gap-2 text-xs">
            <span className="text-stratus-muted">Session:</span>
            <span className="font-mono">{activeSession.session_name || shortUUID(activeSession.uuid)}</span>
            {healthBadge(activeSession.health_status)}
            <Badge label={activeSession.region} variant="blue" />
          </div>
        )}

        {workspace && (
          <button
            onClick={onCloseWorkspace}
            className="text-xs text-stratus-muted hover:text-stratus-text transition-colors"
            title="Close workspace"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
            </svg>
          </button>
        )}
      </div>
    </header>
  );
}
