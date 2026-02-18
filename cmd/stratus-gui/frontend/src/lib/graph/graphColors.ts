// Node colors by AWS principal type
export const nodeColors: Record<string, string> = {
  iam_user: '#3B82F6',       // Blue
  iam_role: '#10B981',       // Green
  account_root: '#F59E0B',   // Amber
  assumed_role: '#8B5CF6',   // Purple
  service: '#F97316',        // Orange
  lambda_function: '#EC4899', // Pink
  ec2_instance: '#6366F1',   // Indigo
  unknown: '#6B7280',        // Gray
};

// Edge styles by relationship type
export const edgeStyles: Record<string, { color: string; dash: string; opacity: number }> = {
  can_assume: { color: '#10B981', dash: '', opacity: 1 },
  trust: { color: '#F59E0B', dash: '6,4', opacity: 1 },
  can_read: { color: '#3B82F6', dash: '3,3', opacity: 1 },
  can_write: { color: '#EF4444', dash: '', opacity: 1 },
  can_invoke: { color: '#8B5CF6', dash: '4,4', opacity: 1 },
  scp_boundary: { color: '#6B7280', dash: '8,4', opacity: 0.6 },
};

export const staleOpacity = 0.4;

// Legend entries for display
export const nodeLegend = [
  { type: 'iam_user', label: 'IAM User', color: nodeColors.iam_user },
  { type: 'iam_role', label: 'IAM Role', color: nodeColors.iam_role },
  { type: 'account_root', label: 'Account Root', color: nodeColors.account_root },
  { type: 'assumed_role', label: 'Assumed Role', color: nodeColors.assumed_role },
  { type: 'service', label: 'Service', color: nodeColors.service },
];

export const edgeLegend = [
  { type: 'can_assume', label: 'Can Assume', ...edgeStyles.can_assume },
  { type: 'trust', label: 'Trust', ...edgeStyles.trust },
  { type: 'can_read', label: 'Can Read', ...edgeStyles.can_read },
  { type: 'can_write', label: 'Can Write', ...edgeStyles.can_write },
];
