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

export interface CreateWorkspaceRequest {
  name: string;
  description: string;
  passphrase: string;
  accounts: string[];
  regions: string[];
  partition: string;
}

export interface UpdateScopeRequest {
  add_accounts?: string[];
  add_regions?: string[];
  set_partition?: string;
}

export interface ScopeCheckResult {
  in_scope: boolean;
  reason: string;
}

export interface WhoamiResult {
  arn: string;
  account_id: string;
  user_id: string;
  verified: boolean;
  error?: string;
}

export interface SessionHealthResult {
  uuid: string;
  label: string;
  health: string;
  detail: string;
}

export interface PivotAssumeRequest {
  role_arn: string;
  external_id?: string;
  label?: string;
  duration_seconds?: number;
}

export interface PivotAssumeResult {
  session: SessionInfo;
  assumed_role: string;
  expiration: string;
}

export interface ArtifactInfo {
  uuid: string;
  label: string;
  type: string;
  sha256: string;
  size_bytes: number;
  run_uuid?: string;
  session_uuid?: string;
  created_at: string;
}

export interface ArtifactContent extends ArtifactInfo {
  content: string;
  is_text: boolean;
}

export interface VerifyArtifactsResult {
  total: number;
  valid: number;
  corrupt: number;
  all_valid: boolean;
}

export interface ExportRequest {
  format: string;
}

export interface ExportResult {
  content: string;
  format: string;
  filename: string;
}

export interface ImportIMDSRequest {
  access_key: string;
  secret_key: string;
  session_token: string;
  expiry?: string;
  role_name?: string;
  label: string;
  region: string;
}

export interface ImportCredProcessRequest {
  command: string;
  access_key?: string;
  secret_key?: string;
  session_token?: string;
  expiry?: string;
  label: string;
  region: string;
}

export interface ImportAssumeRoleRequest {
  role_arn: string;
  external_id?: string;
  label: string;
}

export interface ImportWebIdentityRequest {
  role_arn: string;
  raw_token: string;
  label: string;
}

export interface ImportIdentityOnlyResult {
  identity: IdentityInfo;
}

// IAM Privilege Escalation Analyzer structured outputs
export interface PrivEscFinding {
  principal_type: string;
  principal_name: string;
  principal_arn: string;
  finding: string;
  description: string;
  required_actions: string[];
  severity: string;
  reference: string;
}

export interface PrivEscAnalysis {
  principals_scanned: number;
  privesc_paths: PrivEscFinding[];
  high_risk_count: number;
  admin_principals: string[];
}

export interface AWSExplorerRequest {
  service: string;
  action: string;
  region?: string;
  params?: Record<string, any>;
}

export interface AWSExplorerResult {
  service: string;
  action: string;
  data: any;
  raw_json: string;
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
