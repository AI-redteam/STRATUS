import React, { useState, useMemo } from 'react';
import type { AttackPathAnalysis, AttackChain, AttackStep } from '../types/api';
import * as api from '../hooks/useWails';
import { Badge } from '../components/shared/Badge';
import { DetailPanel, DetailRow } from '../components/shared/DetailPanel';
import { LoadingState, ErrorBanner } from '../components/shared/Spinner';
import { truncateARN } from '../lib/format';

function severityBadge(severity: string) {
  const map: Record<string, 'red' | 'yellow' | 'blue' | 'gray'> = {
    critical: 'red',
    high: 'yellow',
    medium: 'blue',
    low: 'gray',
  };
  return <Badge label={severity} variant={map[severity] || 'gray'} />;
}

function scoreBar(score: number) {
  const pct = Math.min(100, Math.max(0, (score / 6) * 100));
  const color = score >= 4 ? 'bg-red-500' : score >= 2 ? 'bg-amber-500' : 'bg-blue-500';
  return (
    <div className="flex items-center gap-2">
      <div className="w-20 h-2 bg-stratus-bg rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs font-mono">{score.toFixed(2)}</span>
    </div>
  );
}

function actionIcon(action: string) {
  switch (action) {
    case 'can_assume':
    case 'trust':
      return (
        <svg className="w-4 h-4 text-blue-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7h12m0 0l-4-4m4 4l-4 4" />
        </svg>
      );
    case 'exploit_privesc':
      return (
        <svg className="w-4 h-4 text-red-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
        </svg>
      );
    default:
      return (
        <svg className="w-4 h-4 text-stratus-muted shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14 5l7 7m0 0l-7 7m7-7H3" />
        </svg>
      );
  }
}

export function AttackPaths() {
  const [analysis, setAnalysis] = useState<AttackPathAnalysis | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // Controls
  const [targetPattern, setTargetPattern] = useState('');
  const [maxDepth, setMaxDepth] = useState(5);
  const [minSeverity, setMinSeverity] = useState('medium');

  // UI state
  const [expandedChain, setExpandedChain] = useState<number | null>(null);
  const [selectedChain, setSelectedChain] = useState<AttackChain | null>(null);
  const [severityFilter, setSeverityFilter] = useState('');

  const runAnalysis = async () => {
    setLoading(true);
    setError('');
    setAnalysis(null);
    setExpandedChain(null);
    setSelectedChain(null);
    try {
      const result = await api.analyzeAttackPaths(targetPattern, maxDepth, minSeverity);
      setAnalysis(result);
    } catch (e: any) {
      setError(typeof e === 'string' ? e : (e?.message || 'Analysis failed'));
    }
    setLoading(false);
  };

  // Determine max severity per chain for filtering
  const chainMaxSeverity = (chain: AttackChain): string => {
    let max = 'info';
    const rank: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
    for (const step of chain.steps || []) {
      if ((rank[step.severity] ?? 0) > (rank[max] ?? 0)) {
        max = step.severity;
      }
    }
    return max;
  };

  const filteredChains = useMemo(() => {
    if (!analysis?.attack_chains) return [];
    return analysis.attack_chains.filter(c => {
      if (severityFilter && chainMaxSeverity(c) !== severityFilter) return false;
      return true;
    });
  }, [analysis, severityFilter]);

  if (loading) return <LoadingState message="Analyzing attack paths..." />;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-xl font-bold">Attack Path Analysis</h1>
      </div>

      {/* Controls */}
      <div className="card">
        <div className="flex items-end gap-4 flex-wrap">
          <div className="flex-1 min-w-[180px]">
            <label className="block text-xs text-stratus-muted mb-1">Target Pattern</label>
            <input
              type="text"
              className="input-field w-full"
              placeholder="e.g. *AdminRole* (empty = all)"
              value={targetPattern}
              onChange={e => setTargetPattern(e.target.value)}
            />
          </div>
          <div className="w-28">
            <label className="block text-xs text-stratus-muted mb-1">Max Depth</label>
            <input
              type="number"
              className="input-field w-full"
              min={1}
              max={10}
              value={maxDepth}
              onChange={e => setMaxDepth(parseInt(e.target.value) || 5)}
            />
          </div>
          <div className="w-32">
            <label className="block text-xs text-stratus-muted mb-1">Min Severity</label>
            <select
              className="input-field w-full"
              value={minSeverity}
              onChange={e => setMinSeverity(e.target.value)}
            >
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </div>
          <button
            className="btn-primary px-6 py-2"
            onClick={runAnalysis}
            disabled={loading}
          >
            Analyze
          </button>
        </div>
      </div>

      {error && <ErrorBanner message={error} onRetry={runAnalysis} />}

      {analysis && (
        <>
          {/* Summary stat cards */}
          <div className="grid grid-cols-4 gap-4">
            <div className="card">
              <p className="text-xs text-stratus-muted uppercase">Attack Chains</p>
              <p className="text-2xl font-bold mt-1 text-amber-400">{analysis.chain_count}</p>
            </div>
            <div className="card">
              <p className="text-xs text-stratus-muted uppercase">High-Value Targets</p>
              <p className="text-2xl font-bold mt-1 text-red-400">
                {(analysis.high_value_targets || []).length}
              </p>
            </div>
            <div className="card">
              <p className="text-xs text-stratus-muted uppercase">Reachable Roles</p>
              <p className="text-2xl font-bold mt-1">{(analysis.reachable_roles || []).length}</p>
            </div>
            <div className="card">
              <p className="text-xs text-stratus-muted uppercase">Avg Chain Length</p>
              <p className="text-2xl font-bold mt-1">
                {analysis.summary?.avg_chain_length?.toFixed(1) ?? '0'}
              </p>
            </div>
          </div>

          {/* High-value targets banner */}
          {(analysis.high_value_targets || []).length > 0 && (
            <div className="bg-red-900/20 border border-red-700 rounded-lg p-4">
              <h3 className="text-sm font-semibold text-red-400 mb-2">
                High-Value Targets (Admin Principals)
              </h3>
              <div className="flex flex-wrap gap-2">
                {analysis.high_value_targets.map(arn => (
                  <span key={arn} className="inline-flex items-center px-2.5 py-1 bg-red-900/40 border border-red-700 rounded text-xs font-mono text-red-300">
                    {truncateARN(arn, 60)}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Chain filter */}
          <div className="flex items-center gap-2">
            <select
              className="input-field w-32"
              value={severityFilter}
              onChange={e => setSeverityFilter(e.target.value)}
            >
              <option value="">All Severity</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <span className="text-xs text-stratus-muted ml-auto">
              {filteredChains.length} of {analysis.chain_count} chains
            </span>
          </div>

          {/* Chain list */}
          {filteredChains.length === 0 ? (
            <div className="card text-center py-12 text-stratus-muted text-sm">
              No attack chains found matching the current filters.
            </div>
          ) : (
            <div className="space-y-2">
              {filteredChains.map(chain => {
                const isExpanded = expandedChain === chain.rank;
                const maxSev = chainMaxSeverity(chain);
                return (
                  <div key={chain.rank} className="card p-0 overflow-hidden">
                    {/* Chain header row */}
                    <button
                      className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-stratus-bg/30 transition-colors"
                      onClick={() => setExpandedChain(isExpanded ? null : chain.rank)}
                    >
                      <span className="text-xs font-mono text-stratus-muted w-8">
                        #{chain.rank}
                      </span>
                      {severityBadge(maxSev)}
                      <span className="font-mono text-sm flex-1 truncate" title={chain.target}>
                        {truncateARN(chain.target, 60)}
                      </span>
                      {scoreBar(chain.chain_score)}
                      <span className="text-xs text-stratus-muted w-16 text-right">
                        {chain.total_hops} hop{chain.total_hops !== 1 ? 's' : ''}
                      </span>
                      <div className="flex gap-1">
                        {(chain.services_involved || []).map(svc => (
                          <Badge key={svc} label={svc} variant="gray" />
                        ))}
                      </div>
                      <svg
                        className={`w-4 h-4 text-stratus-muted transition-transform ${isExpanded ? 'rotate-180' : ''}`}
                        fill="none" stroke="currentColor" viewBox="0 0 24 24"
                      >
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                      </svg>
                    </button>

                    {/* Expanded steps */}
                    {isExpanded && (
                      <div className="border-t border-stratus-border px-4 py-3 bg-stratus-bg/20">
                        <div className="space-y-3">
                          {(chain.steps || []).map((step: AttackStep) => (
                            <div key={step.step_number} className="flex items-start gap-3">
                              <div className="flex items-center gap-2 w-8 pt-0.5">
                                {actionIcon(step.action)}
                              </div>
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2">
                                  <span className="text-xs font-mono text-stratus-muted">
                                    Step {step.step_number}
                                  </span>
                                  <Badge
                                    label={step.action.replace('_', ' ')}
                                    variant={step.action === 'exploit_privesc' ? 'red' : 'blue'}
                                  />
                                  {step.severity !== 'info' && severityBadge(step.severity)}
                                  <span className="text-xs text-stratus-muted">
                                    confidence: {(step.confidence * 100).toFixed(0)}%
                                  </span>
                                </div>
                                <div className="mt-1 text-xs">
                                  <span className="font-mono text-stratus-muted">{truncateARN(step.from, 40)}</span>
                                  <span className="text-stratus-muted mx-1">{'->'}</span>
                                  <span className="font-mono text-stratus-text">{truncateARN(step.to, 40)}</span>
                                </div>
                                <p className="text-xs text-stratus-muted mt-1 line-clamp-2">
                                  {step.description}
                                </p>
                                {step.required_actions && step.required_actions.length > 0 && (
                                  <div className="flex flex-wrap gap-1 mt-1">
                                    {step.required_actions.map(a => (
                                      <span key={a} className="text-[10px] font-mono bg-stratus-surface border border-stratus-border rounded px-1.5 py-0.5">
                                        {a}
                                      </span>
                                    ))}
                                  </div>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                        <div className="mt-3 pt-3 border-t border-stratus-border flex justify-end">
                          <button
                            className="text-xs text-stratus-accent hover:underline"
                            onClick={() => setSelectedChain(chain)}
                          >
                            View full detail
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </>
      )}

      {!analysis && !loading && !error && (
        <div className="card text-center py-16">
          <svg className="w-12 h-12 mx-auto text-stratus-muted mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
          </svg>
          <p className="text-stratus-muted text-sm mb-4">
            Click "Analyze" to discover attack paths from your current identity.
          </p>
          <p className="text-stratus-muted text-xs">
            For best results, first run <span className="font-mono text-stratus-accent">pivot graph build</span> and
            privesc modules (e.g., <span className="font-mono text-stratus-accent">iam.policy-analyzer</span>,{' '}
            <span className="font-mono text-stratus-accent">codebuild.privesc-check</span>).
          </p>
        </div>
      )}

      {/* Chain detail panel */}
      <DetailPanel
        open={!!selectedChain}
        onClose={() => setSelectedChain(null)}
        title="Attack Chain Detail"
      >
        {selectedChain && (
          <>
            <div className="flex items-center gap-2 mb-3">
              <Badge label={`#${selectedChain.rank}`} variant="gray" />
              {severityBadge(chainMaxSeverity(selectedChain))}
              <span className="text-xs text-stratus-muted">
                Score: {selectedChain.chain_score.toFixed(2)}
              </span>
            </div>

            <DetailRow label="Target" value={selectedChain.target} mono />
            <DetailRow label="Total Hops" value={String(selectedChain.total_hops)} />
            <DetailRow label="Min Confidence" value={`${(selectedChain.min_confidence * 100).toFixed(0)}%`} />
            <DetailRow label="Services" value={(selectedChain.services_involved || []).join(', ')} />

            <div className="mt-4">
              <dt className="text-xs text-stratus-muted uppercase mb-3">Exploitation Steps</dt>
              <div className="space-y-4">
                {(selectedChain.steps || []).map((step: AttackStep) => (
                  <div key={step.step_number} className="bg-stratus-bg rounded-lg p-3">
                    <div className="flex items-center gap-2 mb-2">
                      {actionIcon(step.action)}
                      <span className="text-xs font-semibold">Step {step.step_number}</span>
                      <Badge
                        label={step.action.replace('_', ' ')}
                        variant={step.action === 'exploit_privesc' ? 'red' : 'blue'}
                      />
                      {step.severity !== 'info' && severityBadge(step.severity)}
                    </div>
                    <div className="text-xs space-y-1 ml-6">
                      <div>
                        <span className="text-stratus-muted">From: </span>
                        <span className="font-mono">{step.from}</span>
                      </div>
                      <div>
                        <span className="text-stratus-muted">To: </span>
                        <span className="font-mono">{step.to}</span>
                      </div>
                      <p className="text-stratus-muted mt-1">{step.description}</p>
                      {step.required_actions && step.required_actions.length > 0 && (
                        <div className="mt-2">
                          <span className="text-stratus-muted">Required Actions:</span>
                          <div className="flex flex-wrap gap-1 mt-1">
                            {step.required_actions.map(a => (
                              <span key={a} className="text-[10px] font-mono bg-stratus-surface border border-stratus-border rounded px-1.5 py-0.5">
                                {a}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                      <div className="text-stratus-muted">
                        Confidence: {(step.confidence * 100).toFixed(0)}%
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </>
        )}
      </DetailPanel>
    </div>
  );
}
