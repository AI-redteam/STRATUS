import React, { useState, useEffect, useRef, useCallback } from 'react';
import type { GraphSnapshot, GraphEdgeInfo } from '../types/api';
import * as api from '../hooks/useWails';
import { ForceGraph, GraphNode, GraphLink } from '../lib/graph/ForceGraph';
import { nodeLegend, edgeLegend } from '../lib/graph/graphColors';
import { Badge } from '../components/shared/Badge';
import { LoadingState, ErrorBanner } from '../components/shared/Spinner';

export function Graph() {
  const svgRef = useRef<SVGSVGElement>(null);
  const graphRef = useRef<ForceGraph | null>(null);
  const [snapshot, setSnapshot] = useState<GraphSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [hops, setHops] = useState<GraphEdgeInfo[]>([]);
  const [tooltip, setTooltip] = useState<{ node: GraphNode; x: number; y: number } | null>(null);

  // Path finder state
  const [pathFrom, setPathFrom] = useState('');
  const [pathTo, setPathTo] = useState('');
  const [pathResult, setPathResult] = useState<string | null>(null);

  useEffect(() => {
    loadGraph();
    return () => { graphRef.current?.destroy(); };
  }, []);

  const loadGraph = async () => {
    setLoading(true);
    setError('');
    try {
      const raw = await api.getGraphSnapshot();
      const data = JSON.parse(raw) as GraphSnapshot;
      setSnapshot(data);
    } catch (e: any) {
      setError(e?.message || 'Failed to load graph');
    }
    setLoading(false);
  };

  useEffect(() => {
    if (!snapshot || !svgRef.current) return;

    const container = svgRef.current.parentElement!;
    const width = container.clientWidth;
    const height = container.clientHeight;

    const graph = new ForceGraph({
      container: svgRef.current,
      width,
      height,
      onNodeClick: handleNodeClick,
      onNodeHover: (node, event) => {
        if (node && event) {
          setTooltip({ node, x: event.clientX, y: event.clientY });
        } else {
          setTooltip(null);
        }
      },
    });

    const nodes: GraphNode[] = (snapshot.nodes || []).map(n => ({
      id: n.id,
      type: n.type,
      label: n.label || n.id.split('/').pop() || n.id,
    }));

    const links: GraphLink[] = (snapshot.edges || []).map(e => ({
      source: e.source_node_id,
      target: e.target_node_id,
      uuid: e.uuid,
      edge_type: e.edge_type,
      confidence: e.confidence,
      is_stale: e.is_stale,
    }));

    graph.update(nodes, links);
    graphRef.current = graph;
  }, [snapshot]);

  const handleNodeClick = useCallback(async (node: GraphNode) => {
    setSelectedNode(node);
    try {
      const h = await api.getHops(node.id);
      setHops(h || []);
    } catch {
      setHops([]);
    }
  }, []);

  const handleFindPath = async () => {
    if (!pathFrom || !pathTo) return;
    setPathResult(null);
    try {
      const result = await api.findPath(pathFrom, pathTo);
      if (result.path && result.path.length > 0) {
        graphRef.current?.highlightPath(result.path.map(e => e.uuid));
        setPathResult(`Path found: ${result.hops} hops, confidence ${(result.confidence * 100).toFixed(0)}%`);
      } else {
        setPathResult('No path found');
      }
    } catch (e: any) {
      setPathResult(e?.message || 'Path search failed');
    }
  };

  const handleClearPath = () => {
    graphRef.current?.clearHighlight();
    setPathResult(null);
    setPathFrom('');
    setPathTo('');
  };

  if (loading) return <LoadingState message="Loading graph..." />;
  if (error) return <ErrorBanner message={error} onRetry={loadGraph} />;

  const nodeIds = snapshot?.nodes?.map(n => n.id) || [];

  return (
    <div className="h-full flex flex-col -m-6">
      {/* Toolbar */}
      <div className="flex items-center gap-3 px-4 py-3 bg-stratus-surface border-b border-stratus-border shrink-0">
        <span className="text-sm font-semibold">Pivot Graph</span>
        <Badge label={`${snapshot?.nodes?.length || 0} nodes`} variant="blue" />
        <Badge label={`${snapshot?.edges?.length || 0} edges`} variant="purple" />

        <div className="ml-auto flex items-center gap-2">
          <select
            className="input-field w-48 text-xs"
            value={pathFrom}
            onChange={e => setPathFrom(e.target.value)}
          >
            <option value="">From node...</option>
            {nodeIds.map(id => <option key={id} value={id}>{id.split('/').pop() || id}</option>)}
          </select>
          <span className="text-stratus-muted text-xs">&rarr;</span>
          <select
            className="input-field w-48 text-xs"
            value={pathTo}
            onChange={e => setPathTo(e.target.value)}
          >
            <option value="">To node...</option>
            {nodeIds.map(id => <option key={id} value={id}>{id.split('/').pop() || id}</option>)}
          </select>
          <button onClick={handleFindPath} className="btn-primary text-xs" disabled={!pathFrom || !pathTo}>
            Find Path
          </button>
          {pathResult && (
            <button onClick={handleClearPath} className="btn-ghost text-xs">Clear</button>
          )}
          <button onClick={loadGraph} className="btn-ghost text-xs">Refresh</button>
        </div>
      </div>

      {pathResult && (
        <div className="px-4 py-2 bg-stratus-surface/50 border-b border-stratus-border text-xs text-stratus-muted">
          {pathResult}
        </div>
      )}

      {/* Graph canvas */}
      <div className="flex-1 relative overflow-hidden">
        {(!snapshot?.nodes || snapshot.nodes.length === 0) ? (
          <div className="flex items-center justify-center h-full text-stratus-muted text-sm">
            No graph data yet. Run reconnaissance modules to discover nodes and edges.
          </div>
        ) : (
          <svg ref={svgRef} className="w-full h-full" />
        )}

        {/* Tooltip */}
        {tooltip && (
          <div
            className="fixed bg-stratus-surface border border-stratus-border rounded-lg shadow-xl px-3 py-2 z-50 pointer-events-none"
            style={{ left: tooltip.x + 12, top: tooltip.y - 12 }}
          >
            <div className="text-xs font-mono">{tooltip.node.id}</div>
            <div className="text-xs text-stratus-muted">{tooltip.node.type}</div>
          </div>
        )}

        {/* Legend */}
        <div className="absolute bottom-4 right-4 bg-stratus-surface/90 border border-stratus-border rounded-lg p-3 text-xs space-y-2">
          <div className="font-semibold text-stratus-muted mb-1">Legend</div>
          {nodeLegend.map(n => (
            <div key={n.type} className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full" style={{ backgroundColor: n.color }} />
              <span>{n.label}</span>
            </div>
          ))}
          <hr className="border-stratus-border" />
          {edgeLegend.map(e => (
            <div key={e.type} className="flex items-center gap-2">
              <div className="w-6 h-0.5" style={{
                backgroundColor: e.color,
                borderTop: e.dash ? `2px dashed ${e.color}` : undefined,
              }} />
              <span>{e.label}</span>
            </div>
          ))}
        </div>

        {/* Selected node sidebar */}
        {selectedNode && (
          <div className="absolute top-4 left-4 w-64 bg-stratus-surface/95 border border-stratus-border rounded-lg p-4 text-xs space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-semibold">Node Detail</span>
              <button onClick={() => setSelectedNode(null)} className="text-stratus-muted hover:text-stratus-text">
                &times;
              </button>
            </div>
            <div className="font-mono break-all">{selectedNode.id}</div>
            <div className="text-stratus-muted">{selectedNode.type}</div>
            {hops.length > 0 && (
              <div className="mt-2">
                <div className="text-stratus-muted mb-1">Outgoing edges ({hops.length}):</div>
                {hops.map(h => (
                  <div key={h.uuid} className="bg-stratus-bg rounded p-1.5 mb-1">
                    <span className="text-stratus-accent">{h.edge_type}</span>
                    <span className="text-stratus-muted"> &rarr; </span>
                    <span className="font-mono">{h.target_node_id.split('/').pop()}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
