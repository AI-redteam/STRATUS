import React, { useEffect, useCallback } from 'react';

interface DetailPanelProps {
  open: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
}

export function DetailPanel({ open, onClose, title, children }: DetailPanelProps) {
  const handleKeyDown = useCallback((e: KeyboardEvent) => {
    if (e.key === 'Escape') onClose();
  }, [onClose]);

  useEffect(() => {
    if (open) {
      document.addEventListener('keydown', handleKeyDown);
      return () => document.removeEventListener('keydown', handleKeyDown);
    }
  }, [open, handleKeyDown]);

  if (!open) return null;

  return (
    <>
      {/* Backdrop */}
      <div className="fixed inset-0 bg-black/40 z-40" onClick={onClose} />

      {/* Panel */}
      <div className="fixed right-0 top-0 bottom-0 w-[480px] bg-stratus-surface border-l border-stratus-border z-50 overflow-y-auto shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-stratus-border sticky top-0 bg-stratus-surface">
          <h2 className="text-lg font-semibold">{title}</h2>
          <button
            onClick={onClose}
            className="p-1 text-stratus-muted hover:text-stratus-text rounded"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <div className="p-6 space-y-4">
          {children}
        </div>
      </div>
    </>
  );
}

// Helper component for detail rows
export function DetailRow({ label, value, mono = false }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div>
      <dt className="text-xs text-stratus-muted uppercase mb-1">{label}</dt>
      <dd className={`text-sm ${mono ? 'font-mono' : ''}`}>{value || '—'}</dd>
    </div>
  );
}
