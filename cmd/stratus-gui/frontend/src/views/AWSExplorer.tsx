import React, { useState, useCallback } from 'react';
import * as api from '../hooks/useWails';
import { Badge } from '../components/shared/Badge';
import { ErrorBanner, Spinner } from '../components/shared/Spinner';

interface ServiceAction {
  action: string;
  label: string;
  params?: { name: string; placeholder: string; required?: boolean }[];
}

interface ServiceDef {
  id: string;
  label: string;
  actions: ServiceAction[];
}

interface CachedResult {
  json: string;
  timestamp: number;
}

const services: ServiceDef[] = [
  {
    id: 'iam', label: 'IAM',
    actions: [
      { action: 'users', label: 'List Users' },
      { action: 'roles', label: 'List Roles' },
      { action: 'policies', label: 'List Policies' },
      { action: 'user-detail', label: 'User Detail', params: [{ name: 'user_name', placeholder: 'User name', required: true }] },
      { action: 'role-detail', label: 'Role Detail', params: [{ name: 'role_name', placeholder: 'Role name', required: true }] },
    ],
  },
  {
    id: 's3', label: 'S3',
    actions: [
      { action: 'buckets', label: 'List Buckets' },
      { action: 'bucket-policy', label: 'Bucket Policy', params: [{ name: 'bucket', placeholder: 'Bucket name', required: true }] },
    ],
  },
  {
    id: 'ec2', label: 'EC2',
    actions: [
      { action: 'instances', label: 'List Instances' },
      { action: 'security-groups', label: 'Security Groups' },
      { action: 'vpcs', label: 'VPCs' },
      { action: 'regions', label: 'List Regions' },
    ],
  },
  {
    id: 'lambda', label: 'Lambda',
    actions: [
      { action: 'functions', label: 'List Functions' },
    ],
  },
  {
    id: 'secrets', label: 'Secrets Manager',
    actions: [
      { action: 'list', label: 'List Secrets' },
    ],
  },
  {
    id: 'ssm', label: 'Systems Manager',
    actions: [
      { action: 'parameters', label: 'List Parameters' },
    ],
  },
  {
    id: 'cloudtrail', label: 'CloudTrail',
    actions: [
      { action: 'events', label: 'Recent Events' },
    ],
  },
  {
    id: 'kms', label: 'KMS',
    actions: [
      { action: 'keys', label: 'List Keys' },
    ],
  },
  {
    id: 'logs', label: 'CloudWatch Logs',
    actions: [
      { action: 'groups', label: 'Log Groups', params: [{ name: 'prefix', placeholder: 'Prefix filter (optional)' }] },
    ],
  },
];

export function AWSExplorer() {
  const [selectedService, setSelectedService] = useState<string>('iam');
  const [selectedAction, setSelectedAction] = useState<string>('users');
  const [regionOverride, setRegionOverride] = useState('');
  const [paramValues, setParamValues] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // Cache results per service.action key — persists across tab switches
  const [resultCache, setResultCache] = useState<Record<string, CachedResult>>({});

  const cacheKey = `${selectedService}.${selectedAction}`;
  const cachedResult = resultCache[cacheKey];

  const currentService = services.find(s => s.id === selectedService);
  const currentAction = currentService?.actions.find(a => a.action === selectedAction);

  const handleServiceChange = (svcId: string) => {
    setSelectedService(svcId);
    const svc = services.find(s => s.id === svcId);
    if (svc && svc.actions.length > 0) {
      setSelectedAction(svc.actions[0].action);
    }
    setParamValues({});
    setError('');
  };

  const handleActionChange = (action: string) => {
    setSelectedAction(action);
    setParamValues({});
    setError('');
  };

  const handleExecute = useCallback(async () => {
    if (!currentAction) return;

    // Validate required params
    for (const p of currentAction.params || []) {
      if (p.required && !paramValues[p.name]?.trim()) {
        setError(`${p.placeholder} is required`);
        return;
      }
    }

    setLoading(true);
    setError('');
    try {
      const params: Record<string, any> = {};
      for (const [k, v] of Object.entries(paramValues)) {
        if (v.trim()) params[k] = v.trim();
      }

      const res = await api.awsExplore({
        service: selectedService,
        action: selectedAction,
        region: regionOverride || undefined,
        params: Object.keys(params).length > 0 ? params : undefined,
      });

      setResultCache(prev => ({
        ...prev,
        [cacheKey]: { json: res.raw_json, timestamp: Date.now() },
      }));
    } catch (e: any) {
      setError(typeof e === 'string' ? e : (e?.message || 'Execution failed'));
    }
    setLoading(false);
  }, [currentAction, paramValues, selectedService, selectedAction, regionOverride, cacheKey]);

  const handleCopy = () => {
    if (cachedResult) {
      navigator.clipboard.writeText(cachedResult.json);
    }
  };

  const handleClearCache = () => {
    setResultCache({});
  };

  const cachedCount = Object.keys(resultCache).length;

  return (
    <div className="flex h-full gap-4">
      {/* Service tree panel */}
      <div className="w-56 shrink-0 space-y-1 overflow-y-auto">
        <h1 className="text-xl font-bold mb-4">AWS Explorer</h1>
        {services.map(svc => (
          <div key={svc.id}>
            <button
              onClick={() => handleServiceChange(svc.id)}
              className={`w-full text-left px-3 py-2 rounded text-sm transition-colors ${
                selectedService === svc.id
                  ? 'bg-stratus-accent/10 text-stratus-accent font-medium'
                  : 'text-stratus-muted hover:text-stratus-text hover:bg-stratus-bg/50'
              }`}
            >
              {svc.label}
            </button>
            {selectedService === svc.id && (
              <div className="ml-3 mt-1 space-y-0.5">
                {svc.actions.map(act => {
                  const actKey = `${svc.id}.${act.action}`;
                  const hasCached = !!resultCache[actKey];
                  return (
                    <button
                      key={act.action}
                      onClick={() => handleActionChange(act.action)}
                      className={`w-full text-left px-3 py-1.5 rounded text-xs transition-colors flex items-center justify-between ${
                        selectedAction === act.action
                          ? 'bg-stratus-accent/5 text-stratus-accent'
                          : 'text-stratus-muted hover:text-stratus-text'
                      }`}
                    >
                      <span>{act.label}</span>
                      {hasCached && <span className="w-1.5 h-1.5 rounded-full bg-green-400 shrink-0" />}
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        ))}
        {cachedCount > 0 && (
          <div className="pt-3 mt-3 border-t border-stratus-border">
            <button onClick={handleClearCache} className="text-xs text-stratus-muted hover:text-stratus-text">
              Clear cache ({cachedCount})
            </button>
          </div>
        )}
      </div>

      {/* Main content */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Controls */}
        <div className="card mb-4">
          <div className="flex items-center gap-3 mb-3">
            <Badge label={selectedService.toUpperCase()} variant="blue" />
            <span className="text-sm font-medium">{currentAction?.label || selectedAction}</span>
            {cachedResult && (
              <span className="text-xs text-stratus-muted">
                (cached {new Date(cachedResult.timestamp).toLocaleTimeString()})
              </span>
            )}
          </div>

          {/* Action params */}
          {currentAction?.params && currentAction.params.length > 0 && (
            <div className="flex flex-wrap gap-2 mb-3">
              {currentAction.params.map(p => (
                <input
                  key={p.name}
                  type="text"
                  className="input-field text-xs w-48"
                  placeholder={p.placeholder}
                  value={paramValues[p.name] || ''}
                  onChange={e => setParamValues(prev => ({ ...prev, [p.name]: e.target.value }))}
                />
              ))}
            </div>
          )}

          <div className="flex items-center gap-2">
            <input
              type="text"
              className="input-field text-xs w-36"
              placeholder="Region override"
              value={regionOverride}
              onChange={e => setRegionOverride(e.target.value)}
            />
            <button
              onClick={handleExecute}
              disabled={loading}
              className="btn-primary text-xs flex items-center gap-1"
            >
              {loading && <Spinner size="sm" />}
              {loading ? 'Executing...' : cachedResult ? 'Re-execute' : 'Execute'}
            </button>
            {cachedResult && (
              <button onClick={handleCopy} className="btn-ghost text-xs">
                Copy
              </button>
            )}
          </div>

          {error && <div className="mt-2"><ErrorBanner message={error} /></div>}
        </div>

        {/* Results */}
        {cachedResult && (
          <div className="card flex-1 overflow-auto">
            <pre className="text-xs font-mono whitespace-pre-wrap break-all">
              {cachedResult.json}
            </pre>
          </div>
        )}

        {!cachedResult && !loading && (
          <div className="card flex-1 flex items-center justify-center">
            <p className="text-sm text-stratus-muted">Select a service and action, then click Execute</p>
          </div>
        )}
      </div>
    </div>
  );
}
