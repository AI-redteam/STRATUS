// Formatting utilities for dates, ARNs, UUIDs

export function formatDate(iso: string): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleDateString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

export function shortDate(iso: string): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

export function relativeTime(iso: string): string {
  if (!iso) return '—';
  const now = Date.now();
  const then = new Date(iso).getTime();
  const diff = now - then;
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export function shortUUID(uuid: string): string {
  if (!uuid) return '—';
  return uuid.slice(0, 8);
}

export function truncateARN(arn: string, maxLen = 40): string {
  if (!arn) return '—';
  if (arn.length <= maxLen) return arn;
  // Show the resource part
  const parts = arn.split(':');
  if (parts.length >= 6) {
    const resource = parts.slice(5).join(':');
    const prefix = parts.slice(0, 3).join(':');
    return `${prefix}:...:${resource}`;
  }
  return arn.slice(0, maxLen - 3) + '...';
}

export function titleCase(s: string): string {
  return s.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}
