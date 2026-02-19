import React, { useState, useEffect, useCallback } from 'react';
import { Routes, Route } from 'react-router-dom';
import { Sidebar } from './components/layout/Sidebar';
import { Header } from './components/layout/Header';
import { WorkspaceSelector } from './views/WorkspaceSelector';
import { Dashboard } from './views/Dashboard';
import { Identities } from './views/Identities';
import { Sessions } from './views/Sessions';
import { Modules } from './views/Modules';
import { Graph } from './views/Graph';
import { Audit } from './views/Audit';
import { Artifacts } from './views/Artifacts';
import { Notes } from './views/Notes';
import { AWSExplorer } from './views/AWSExplorer';
import type { WorkspaceInfo, SessionInfo } from './types/api';
import * as api from './hooks/useWails';

export function App() {
  const [workspace, setWorkspace] = useState<WorkspaceInfo | null>(null);
  const [activeSession, setActiveSession] = useState<SessionInfo | null>(null);
  const [wsOpen, setWsOpen] = useState(false);

  const refreshState = useCallback(async () => {
    try {
      const open = await api.isWorkspaceOpen();
      setWsOpen(open);
      if (open) {
        const ws = await api.getWorkspace();
        setWorkspace(ws);
        try {
          const sess = await api.getActiveSession();
          setActiveSession(sess);
        } catch {
          setActiveSession(null);
        }
      } else {
        setWorkspace(null);
        setActiveSession(null);
      }
    } catch {
      // Wails not ready yet
    }
  }, []);

  useEffect(() => {
    refreshState();
  }, [refreshState]);

  const handleOpenWorkspace = async (path: string, passphrase: string) => {
    await api.openWorkspace(path, passphrase);
    await refreshState();
  };

  const handleCloseWorkspace = async () => {
    await api.closeWorkspace();
    setWorkspace(null);
    setActiveSession(null);
    setWsOpen(false);
  };

  if (!wsOpen) {
    return <WorkspaceSelector onOpen={handleOpenWorkspace} />;
  }

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <div className="flex flex-col flex-1 overflow-hidden">
        <Header
          workspace={workspace}
          activeSession={activeSession}
          onCloseWorkspace={handleCloseWorkspace}
        />
        <main className="flex-1 overflow-y-auto p-6">
          <Routes>
            <Route path="/" element={<Dashboard onRefresh={refreshState} />} />
            <Route path="/identities" element={<Identities />} />
            <Route path="/sessions" element={<Sessions onSessionChange={refreshState} />} />
            <Route path="/modules" element={<Modules />} />
            <Route path="/graph" element={<Graph />} />
            <Route path="/audit" element={<Audit />} />
            <Route path="/artifacts" element={<Artifacts />} />
            <Route path="/notes" element={<Notes />} />
            <Route path="/aws-explorer" element={<AWSExplorer />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}
