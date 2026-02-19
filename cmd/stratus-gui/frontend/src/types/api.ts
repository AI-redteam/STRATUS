// TypeScript interfaces mirroring all Go response types

export interface WorkspaceInfo {
  uuid: string;
  name: string;
  description: string;
  owner: string;
  created_at: string;
  path: string;
  scope_accounts?: string[];
  scope_regions?: string[];
}

export interface WorkspaceEntry {
  uuid: string;
  name: string;
  path: string;
}

export interface IdentityInfo {
  uuid: string;
  label: string;
  source_type: string;
  principal_arn: string;
  principal_type: string;
  account_id: string;
  acquired_at: string;
}

export interface SessionInfo {
  uuid: string;
  identity_uuid: string;
  session_name: string;
  region: string;
  health_status: string;
  expiry?: string;
  is_active: boolean;
}

export interface GraphEdgeInfo {
  uuid: string;
  source_node_id: string;
  target_node_id: string;
  edge_type: string;
  confidence: number;
}

export interface GraphPathResult {
  path: GraphEdgeInfo[];
  hops: number;
  confidence: number;
}

export interface GraphStats {
  nodes: number;
  edges: number;
  stale_edges: number;
}

export interface InputSpec {
  name: string;
  type: string;
  default?: any;
  description: string;
  required?: boolean;
}

export interface OutputSpec {
  name: string;
  type: string;
  description: string;
}

export interface ModuleInfo {
  id: string;
  name: string;
  version: string;
  description: string;
  risk_class: string;
  services: string[];
  author: string;
  inputs?: InputSpec[];
  outputs?: OutputSpec[];
  references?: string[];
  required_actions?: string[];
}

export interface RunModuleRequest {
  module_id: string;
  inputs?: Record<string, any>;
  dry_run: boolean;
  operator: string;
}

export interface RunModuleResult {
  run_uuid: string;
  status: string;
  outputs?: Record<string, any>;
  error?: string;
  duration?: string;
  artifact_ids?: string[];
}

export interface RunInfo {
  uuid: string;
  module_id: string;
  module_version: string;
  status: string;
  started_at: string;
  completed_at?: string;
  output_json?: string;
  error?: string;
}

export interface AuditEntry {
  id: number;
  timestamp: string;
  session_uuid?: string;
  run_uuid?: string;
  operator: string;
  event_type: string;
  detail: string;
  record_hash: string;
}

export interface ScopeInfo {
  account_ids?: string[];
  regions?: string[];
  partition?: string;
  org_id?: string;
}

export interface NoteInfo {
  uuid: string;
  session_uuid?: string;
  run_uuid?: string;
  node_id?: string;
  content: string;
  created_at: string;
  updated_at: string;
  created_by: string;
}

export interface ImportIAMKeyRequest {
  access_key: string;
  secret_key: string;
  label: string;
  region: string;
}

export interface ImportSTSSessionRequest {
  access_key: string;
  secret_key: string;
  session_token: string;
  label: string;
  region: string;
}

export interface ImportResult {
  identity: IdentityInfo;
  session: SessionInfo;
}

export interface AddNoteRequest {
  content: string;
  session_uuid?: string;
  run_uuid?: string;
  node_id?: string;
}

export interface GraphSnapshot {
  workspace_uuid: string;
  timestamp: string;
  nodes: GraphNode[];
  edges: GraphSnapshotEdge[];
}

export interface GraphNode {
  id: string;
  type: string;
  label: string;
  metadata?: Record<string, any>;
}

export interface GraphSnapshotEdge {
  uuid: string;
  source_node_id: string;
  target_node_id: string;
  edge_type: string;
  confidence: number;
  is_stale: boolean;
}
