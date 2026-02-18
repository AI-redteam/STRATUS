import React, { useState, useEffect } from 'react';
import type { ModuleInfo, RunModuleRequest, RunModuleResult, RunInfo } from '../types/api';
import * as api from '../hooks/useWails';
import { riskBadge, Badge, statusBadge } from '../components/shared/Badge';
import { DetailPanel, DetailRow } from '../components/shared/DetailPanel';
import { DataTable, Column } from '../components/shared/DataTable';
import { LoadingState, ErrorBanner, Spinner } from '../components/shared/Spinner';
import { formatDate, shortUUID } from '../lib/format';

export function Modules() {
  const [modules, setModules] = useState<ModuleInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [serviceFilter, setServiceFilter] = useState('');
  const [riskFilter, setRiskFilter] = useState('');
  const [selected, setSelected] = useState<ModuleInfo | null>(null);
  const [showRunDialog, setShowRunDialog] = useState(false);
  const [runInputs, setRunInputs] = useState<Record<string, any>>({});
  const [dryRun, setDryRun] = useState(false);
  const [running, setRunning] = useState(false);
  const [runResult, setRunResult] = useState<RunModuleResult | null>(null);
  const [runs, setRuns] = useState<RunInfo[]>([]);

  useEffect(() => { loadModules(); }, []);

  const loadModules = async () => {
    setLoading(true);
    setError('');
    try {
      const [mods, r] = await Promise.all([
        api.listModules('', '', ''),
        api.listRuns('', ''),
      ]);
      setModules(mods || []);
      setRuns(r || []);
    } catch (e: any) {
      setError(e?.message || 'Failed to load modules');
    }
    setLoading(false);
  };

  // Unique services for filter dropdown
  const allServices = [...new Set(modules.flatMap(m => m.services))].sort();

  const filtered = modules.filter(m => {
    if (search) {
      const q = search.toLowerCase();
      if (!m.name.toLowerCase().includes(q) && !m.id.toLowerCase().includes(q) && !m.description.toLowerCase().includes(q)) {
        return false;
      }
    }
    if (serviceFilter && !m.services.includes(serviceFilter)) return false;
    if (riskFilter && m.risk_class !== riskFilter) return false;
    return true;
  });

  const openRunDialog = (mod: ModuleInfo) => {
    setSelected(mod);
    setShowRunDialog(true);
    setRunResult(null);
    setDryRun(false);
    // Set defaults
    const defaults: Record<string, any> = {};
    mod.inputs?.forEach(inp => {
      if (inp.default !== undefined && inp.default !== null) {
        defaults[inp.name] = inp.default;
      }
    });
    setRunInputs(defaults);
  };

  const executeModule = async () => {
    if (!selected) return;
    setRunning(true);
    setRunResult(null);
    try {
      const req: RunModuleRequest = {
        module_id: selected.id,
        inputs: runInputs,
        dry_run: dryRun,
        operator: 'gui',
      };
      const result = await api.runModule(req);
      setRunResult(result);
      // Refresh runs
      const r = await api.listRuns('', '');
      setRuns(r || []);
    } catch (e: any) {
      setRunResult({ run_uuid: '', status: 'error', error: e?.message || 'Execution failed' });
    }
    setRunning(false);
  };

  if (loading) return <LoadingState message="Loading modules..." />;
  if (error) return <ErrorBanner message={error} onRetry={loadModules} />;

  return (
    <div className="space-y-6">
      {/* Header + Filters */}
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-xl font-bold">Modules</h1>
        <div className="flex gap-2">
          <input
            type="text"
            className="input-field w-48"
            placeholder="Search..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
          <select
            className="input-field w-32"
            value={serviceFilter}
            onChange={e => setServiceFilter(e.target.value)}
          >
            <option value="">All Services</option>
            {allServices.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <select
            className="input-field w-32"
            value={riskFilter}
            onChange={e => setRiskFilter(e.target.value)}
          >
            <option value="">All Risk</option>
            <option value="read_only">Read Only</option>
            <option value="write">Write</option>
            <option value="destructive">Destructive</option>
          </select>
        </div>
      </div>

      {/* Module grid */}
      {filtered.length === 0 ? (
        <div className="text-center py-12 text-stratus-muted text-sm">No modules match filters</div>
      ) : (
        <div className="grid grid-cols-3 gap-4">
          {filtered.map(mod => (
            <div
              key={mod.id}
              className="card cursor-pointer hover:border-stratus-accent/50 transition-colors"
              onClick={() => setSelected(mod)}
            >
              <div className="flex items-start justify-between mb-2">
                <h3 className="text-sm font-semibold">{mod.name}</h3>
                {riskBadge(mod.risk_class)}
              </div>
              <p className="text-xs text-stratus-muted mb-3 line-clamp-2">{mod.description}</p>
              <div className="flex items-center gap-2 flex-wrap">
                {mod.services.map(s => (
                  <Badge key={s} label={s} variant="blue" />
                ))}
                <span className="text-xs text-stratus-muted ml-auto">v{mod.version}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Module detail panel */}
      <DetailPanel
        open={!!selected && !showRunDialog}
        onClose={() => setSelected(null)}
        title={selected?.name || 'Module Detail'}
      >
        {selected && (
          <>
            <DetailRow label="ID" value={selected.id} mono />
            <DetailRow label="Version" value={selected.version} />
            <DetailRow label="Author" value={selected.author || '—'} />
            <DetailRow label="Risk Class" value={riskBadge(selected.risk_class)} />
            <DetailRow label="Description" value={selected.description} />
            <DetailRow label="Services" value={
              <div className="flex gap-1 flex-wrap">
                {selected.services.map(s => <Badge key={s} label={s} variant="blue" />)}
              </div>
            } />

            {selected.inputs && selected.inputs.length > 0 && (
              <div>
                <dt className="text-xs text-stratus-muted uppercase mb-2">Inputs</dt>
                <div className="space-y-1">
                  {selected.inputs.map(inp => (
                    <div key={inp.name} className="text-xs bg-stratus-bg rounded p-2">
                      <span className="font-mono text-stratus-accent">{inp.name}</span>
                      <span className="text-stratus-muted ml-2">({inp.type})</span>
                      {inp.required && <span className="text-red-400 ml-1">*</span>}
                      <p className="text-stratus-muted mt-0.5">{inp.description}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {selected.required_actions && selected.required_actions.length > 0 && (
              <DetailRow label="Required IAM Actions" value={
                <div className="font-mono text-xs space-y-0.5">
                  {selected.required_actions.map(a => <div key={a}>{a}</div>)}
                </div>
              } />
            )}

            {selected.references && selected.references.length > 0 && (
              <DetailRow label="References" value={
                <div className="text-xs space-y-0.5">
                  {selected.references.map(r => <div key={r}>{r}</div>)}
                </div>
              } />
            )}

            {/* Run history for this module */}
            <div className="mt-4">
              <h4 className="text-xs text-stratus-muted uppercase mb-2">Run History</h4>
              <div className="space-y-1">
                {runs.filter(r => r.module_id === selected.id).slice(0, 5).map(r => (
                  <div key={r.uuid} className="text-xs bg-stratus-bg rounded p-2 flex items-center justify-between">
                    <span className="font-mono">{shortUUID(r.uuid)}</span>
                    {statusBadge(r.status)}
                    <span className="text-stratus-muted">{formatDate(r.started_at)}</span>
                  </div>
                ))}
                {runs.filter(r => r.module_id === selected.id).length === 0 && (
                  <p className="text-xs text-stratus-muted">No runs yet</p>
                )}
              </div>
            </div>

            <div className="mt-6 pt-4 border-t border-stratus-border">
              <button onClick={() => openRunDialog(selected)} className="btn-primary text-xs">
                Run Module
              </button>
            </div>
          </>
        )}
      </DetailPanel>

      {/* Run dialog */}
      <DetailPanel
        open={showRunDialog}
        onClose={() => { setShowRunDialog(false); setRunResult(null); }}
        title={`Run: ${selected?.name || ''}`}
      >
        {selected && (
          <div className="space-y-4">
            {/* Auto-generated inputs */}
            {selected.inputs && selected.inputs.length > 0 && (
              <div className="space-y-3">
                {selected.inputs.map(inp => (
                  <div key={inp.name}>
                    <label className="block text-xs text-stratus-muted mb-1">
                      {inp.name}
                      {inp.required && <span className="text-red-400 ml-1">*</span>}
                    </label>
                    {inp.type === 'bool' ? (
                      <label className="flex items-center gap-2">
                        <input
                          type="checkbox"
                          checked={!!runInputs[inp.name]}
                          onChange={e => setRunInputs({ ...runInputs, [inp.name]: e.target.checked })}
                          className="rounded"
                        />
                        <span className="text-xs text-stratus-muted">{inp.description}</span>
                      </label>
                    ) : inp.type === 'int' ? (
                      <input
                        type="number"
                        className="input-field"
                        value={runInputs[inp.name] ?? ''}
                        onChange={e => setRunInputs({ ...runInputs, [inp.name]: parseInt(e.target.value) || 0 })}
                        placeholder={inp.description}
                      />
                    ) : (
                      <input
                        type="text"
                        className="input-field"
                        value={runInputs[inp.name] ?? ''}
                        onChange={e => setRunInputs({ ...runInputs, [inp.name]: e.target.value })}
                        placeholder={inp.description}
                      />
                    )}
                  </div>
                ))}
              </div>
            )}

            {/* Dry run toggle */}
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={dryRun}
                onChange={e => setDryRun(e.target.checked)}
                className="rounded"
              />
              <span className="text-sm">Dry run (preview only)</span>
            </label>

            {/* Confirm step for write/destructive */}
            {(selected.risk_class === 'write' || selected.risk_class === 'destructive') && !dryRun && (
              <div className="bg-amber-900/20 border border-amber-700 rounded p-3 text-xs text-amber-300">
                This module has <strong>{selected.risk_class}</strong> risk class. It will make changes to your AWS environment.
              </div>
            )}

            {/* Execute button */}
            <button
              onClick={executeModule}
              disabled={running}
              className={`${selected.risk_class === 'destructive' && !dryRun ? 'btn-danger' : 'btn-primary'} w-full flex items-center justify-center gap-2`}
            >
              {running && <Spinner size="sm" />}
              {running ? 'Executing...' : dryRun ? 'Preview' : 'Execute'}
            </button>

            {/* Result */}
            {runResult && (
              <div className="mt-4 space-y-2">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium">Result:</span>
                  {statusBadge(runResult.status)}
                </div>
                {runResult.run_uuid && (
                  <p className="text-xs text-stratus-muted font-mono">Run: {shortUUID(runResult.run_uuid)}</p>
                )}
                {runResult.duration && (
                  <p className="text-xs text-stratus-muted">Duration: {runResult.duration}</p>
                )}
                {runResult.error && (
                  <div className="bg-red-900/30 border border-red-700 rounded p-3 text-xs text-red-300">
                    {runResult.error}
                  </div>
                )}
                {runResult.outputs && Object.keys(runResult.outputs).length > 0 && (
                  <details className="bg-stratus-bg rounded p-3">
                    <summary className="text-xs text-stratus-muted cursor-pointer">Outputs</summary>
                    <pre className="text-xs mt-2 overflow-auto max-h-64">
                      {JSON.stringify(runResult.outputs, null, 2)}
                    </pre>
                  </details>
                )}
              </div>
            )}
          </div>
        )}
      </DetailPanel>
    </div>
  );
}
