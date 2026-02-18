// Typed wrappers around Wails Go bindings.
// Wails generates bindings at wailsjs/go/main/App during build.
// We define a runtime bridge here so the app works in both dev and prod.

import type {
  WorkspaceInfo, WorkspaceEntry, IdentityInfo, SessionInfo,
  GraphEdgeInfo, GraphPathResult, GraphStats, ModuleInfo,
  RunModuleRequest, RunModuleResult, RunInfo, AuditEntry,
  ScopeInfo, NoteInfo, AddNoteRequest,
} from '../types/api';

// At runtime, Wails injects window.go.main.App
// We create a typed accessor that falls back to stubs in dev mode without Wails.
function getApp(): any {
  return (window as any)?.go?.main?.App;
}

async function call<T>(method: string, ...args: any[]): Promise<T> {
  const app = getApp();
  if (!app || !app[method]) {
    throw new Error(`Wails binding not available: ${method}`);
  }
  return app[method](...args);
}

// --- Workspace ---
export const listWorkspaces = () => call<WorkspaceEntry[]>('ListWorkspaces');
export const openWorkspace = (path: string, passphrase: string) => call<void>('OpenWorkspace', path, passphrase);
export const closeWorkspace = () => call<void>('CloseWorkspace');
export const isWorkspaceOpen = () => call<boolean>('IsWorkspaceOpen');
export const getWorkspace = () => call<WorkspaceInfo>('GetWorkspace');

// --- Identity ---
export const listIdentities = () => call<IdentityInfo[]>('ListIdentities');
export const getIdentity = (uuidOrLabel: string) => call<IdentityInfo>('GetIdentity', uuidOrLabel);
export const archiveIdentity = (uuidOrLabel: string) => call<void>('ArchiveIdentity', uuidOrLabel);

// --- Sessions ---
export const listSessions = () => call<SessionInfo[]>('ListSessions');
export const getActiveSession = () => call<SessionInfo | null>('GetActiveSession');
export const activateSession = (uuid: string) => call<SessionInfo>('ActivateSession', uuid);
export const pushSession = (uuid: string) => call<SessionInfo>('PushSession', uuid);
export const popSession = () => call<SessionInfo | null>('PopSession');
export const peekStack = () => call<SessionInfo[]>('PeekStack');
export const expireSession = (uuid: string) => call<void>('ExpireSession', uuid);

// --- Graph ---
export const findPath = (from: string, to: string) => call<GraphPathResult>('FindPath', from, to);
export const getHops = (nodeId: string) => call<GraphEdgeInfo[]>('GetHops', nodeId);
export const getGraphStats = () => call<GraphStats>('GetGraphStats');
export const getGraphSnapshot = () => call<string>('GetGraphSnapshot');

// --- Modules ---
export const listModules = (keyword: string, service: string, riskClass: string) =>
  call<ModuleInfo[]>('ListModules', keyword, service, riskClass);
export const runModule = (req: RunModuleRequest) => call<RunModuleResult>('RunModule', req);
export const getRunStatus = (runUUID: string) => call<RunInfo>('GetRunStatus', runUUID);
export const listRuns = (moduleFilter: string, statusFilter: string) =>
  call<RunInfo[]>('ListRuns', moduleFilter, statusFilter);

// --- Audit ---
export const verifyAuditChain = () => call<{ valid: boolean; count: number }>('VerifyAuditChain');
export const listAuditEvents = (limit: number, offset: number, eventTypeFilter: string) =>
  call<AuditEntry[]>('ListAuditEvents', limit, offset, eventTypeFilter);

// --- Scope ---
export const getScopeInfo = () => call<ScopeInfo>('GetScopeInfo');

// --- Notes ---
export const listNotes = (session: string, run: string, node: string) =>
  call<NoteInfo[]>('ListNotes', session, run, node);
export const getNote = (uuid: string) => call<NoteInfo>('GetNote', uuid);
export const addNote = (req: AddNoteRequest) => call<NoteInfo>('AddNote', req);
export const updateNote = (uuid: string, content: string) => call<void>('UpdateNote', uuid, content);
export const deleteNote = (uuid: string) => call<void>('DeleteNote', uuid);
