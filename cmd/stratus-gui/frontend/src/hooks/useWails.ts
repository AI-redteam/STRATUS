// Typed wrappers around Wails Go bindings.
// Wails generates bindings at wailsjs/go/main/App during build.
// We define a runtime bridge here so the app works in both dev and prod.

import type {
  WorkspaceInfo, WorkspaceEntry, IdentityInfo, SessionInfo,
  GraphEdgeInfo, GraphPathResult, GraphStats, ModuleInfo,
  RunModuleRequest, RunModuleResult, RunInfo, AuditEntry,
  ScopeInfo, NoteInfo, AddNoteRequest,
  ImportIAMKeyRequest, ImportSTSSessionRequest, ImportResult,
  CreateWorkspaceRequest, UpdateScopeRequest, ScopeCheckResult,
  WhoamiResult, SessionHealthResult, PivotAssumeRequest, PivotAssumeResult,
  ArtifactInfo, ArtifactContent, VerifyArtifactsResult, ExportRequest, ExportResult,
  ImportIMDSRequest, ImportCredProcessRequest, ImportAssumeRoleRequest,
  ImportWebIdentityRequest, ImportIdentityOnlyResult,
  AWSExplorerRequest, AWSExplorerResult,
  AttackPathAnalysis,
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
export const importIAMKey = (req: ImportIAMKeyRequest) => call<ImportResult>('ImportIAMKey', req);
export const importSTSSession = (req: ImportSTSSessionRequest) => call<ImportResult>('ImportSTSSession', req);
export const importIMDS = (req: ImportIMDSRequest) => call<ImportResult>('ImportIMDS', req);
export const importCredProcess = (req: ImportCredProcessRequest) => call<ImportResult>('ImportCredProcess', req);
export const importAssumeRoleIdentity = (req: ImportAssumeRoleRequest) => call<ImportIdentityOnlyResult>('ImportAssumeRoleIdentity', req);
export const importWebIdentity = (req: ImportWebIdentityRequest) => call<ImportIdentityOnlyResult>('ImportWebIdentity', req);

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

// --- Workspace creation ---
export const createWorkspace = (req: CreateWorkspaceRequest) => call<WorkspaceInfo>('CreateWorkspace', req);

// --- Scope management ---
export const updateScope = (req: UpdateScopeRequest) => call<ScopeInfo>('UpdateScope', req);
export const checkScope = (region: string, accountID: string) => call<ScopeCheckResult>('CheckScope', region, accountID);

// --- Session intelligence ---
export const sessionWhoami = (uuid: string) => call<WhoamiResult>('SessionWhoami', uuid);
export const sessionHealthCheck = () => call<SessionHealthResult[]>('SessionHealthCheck');
export const refreshSession = (uuid: string) => call<SessionInfo>('RefreshSession', uuid);

// --- Pivot ---
export const pivotAssume = (req: PivotAssumeRequest) => call<PivotAssumeResult>('PivotAssume', req);

// --- Artifacts ---
export const listArtifacts = (runFilter: string, typeFilter: string) => call<ArtifactInfo[]>('ListArtifacts', runFilter, typeFilter);
export const getArtifact = (uuid: string) => call<ArtifactContent>('GetArtifact', uuid);
export const verifyArtifacts = () => call<VerifyArtifactsResult>('VerifyArtifacts');

// --- Export ---
export const exportWorkspace = (req: ExportRequest) => call<ExportResult>('ExportWorkspace', req);

// --- Attack Path Analysis ---
export const analyzeAttackPaths = (targetPattern: string, maxDepth: number, minSeverity: string) =>
  call<AttackPathAnalysis>('AnalyzeAttackPaths', targetPattern, maxDepth, minSeverity);

// --- AWS Explorer ---
export const awsExplore = (req: AWSExplorerRequest) => call<AWSExplorerResult>('AWSExplore', req);
