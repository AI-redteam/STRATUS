import React from 'react';

export function Spinner({ size = 'md' }: { size?: 'sm' | 'md' | 'lg' }) {
  const px = { sm: 'w-4 h-4', md: 'w-6 h-6', lg: 'w-8 h-8' }[size];
  return (
    <svg className={`${px} animate-spin text-stratus-accent`} fill="none" viewBox="0 0 24 24">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
    </svg>
  );
}

export function LoadingState({ message = 'Loading...' }: { message?: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-stratus-muted">
      <Spinner size="lg" />
      <p className="mt-4 text-sm">{message}</p>
    </div>
  );
}

export function ErrorBanner({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="bg-red-900/30 border border-red-700 rounded-lg p-4 flex items-center gap-3">
      <svg className="w-5 h-5 text-red-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>
      <span className="text-sm text-red-300 flex-1">{message}</span>
      {onRetry && (
        <button onClick={onRetry} className="text-xs text-red-400 hover:text-red-300 underline">
          Retry
        </button>
      )}
    </div>
  );
}
