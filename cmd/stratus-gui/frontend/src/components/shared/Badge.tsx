import React from 'react';

type Variant = 'green' | 'yellow' | 'red' | 'blue' | 'purple' | 'gray';

const variants: Record<Variant, string> = {
  green: 'bg-emerald-900/50 text-emerald-400 border-emerald-700',
  yellow: 'bg-amber-900/50 text-amber-400 border-amber-700',
  red: 'bg-red-900/50 text-red-400 border-red-700',
  blue: 'bg-blue-900/50 text-blue-400 border-blue-700',
  purple: 'bg-purple-900/50 text-purple-400 border-purple-700',
  gray: 'bg-slate-700/50 text-slate-400 border-slate-600',
};

interface BadgeProps {
  label: string;
  variant?: Variant;
  className?: string;
}

export function Badge({ label, variant = 'gray', className = '' }: BadgeProps) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 text-xs font-medium border rounded ${variants[variant]} ${className}`}>
      {label}
    </span>
  );
}

// Convenience mappers
export function riskBadge(riskClass: string) {
  const map: Record<string, Variant> = {
    read_only: 'green',
    write: 'yellow',
    destructive: 'red',
  };
  return <Badge label={riskClass.replace('_', ' ')} variant={map[riskClass] || 'gray'} />;
}

export function healthBadge(status: string) {
  const map: Record<string, Variant> = {
    healthy: 'green',
    unverified: 'yellow',
    expired: 'red',
    error: 'red',
  };
  return <Badge label={status} variant={map[status] || 'gray'} />;
}

export function statusBadge(status: string) {
  const map: Record<string, Variant> = {
    success: 'green',
    running: 'blue',
    pending: 'gray',
    error: 'red',
    cancelled: 'gray',
    dry_run: 'purple',
  };
  return <Badge label={status.replace('_', ' ')} variant={map[status] || 'gray'} />;
}

export function eventTypeBadge(eventType: string) {
  const map: Record<string, Variant> = {
    scope_violation: 'red',
    api_call: 'blue',
    module_run: 'green',
    session_activated: 'purple',
    identity_imported: 'blue',
    workspace_created: 'gray',
    session_expired: 'yellow',
  };
  return <Badge label={eventType.replace('_', ' ')} variant={map[eventType] || 'gray'} />;
}
