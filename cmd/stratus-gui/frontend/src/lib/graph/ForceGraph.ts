import * as d3 from 'd3';
import { nodeColors, edgeStyles, staleOpacity } from './graphColors';

export interface GraphNode extends d3.SimulationNodeDatum {
  id: string;
  type: string;
  label: string;
}

export interface GraphLink extends d3.SimulationLinkDatum<GraphNode> {
  uuid: string;
  edge_type: string;
  confidence: number;
  is_stale: boolean;
}

export interface ForceGraphOptions {
  container: SVGSVGElement;
  width: number;
  height: number;
  onNodeClick?: (node: GraphNode) => void;
  onNodeHover?: (node: GraphNode | null, event?: MouseEvent) => void;
}

export class ForceGraph {
  private svg: d3.Selection<SVGSVGElement, unknown, null, undefined>;
  private simulation: d3.Simulation<GraphNode, GraphLink>;
  private linkGroup: d3.Selection<SVGGElement, unknown, null, undefined>;
  private nodeGroup: d3.Selection<SVGGElement, unknown, null, undefined>;
  private zoom: d3.ZoomBehavior<SVGSVGElement, unknown>;
  private container: d3.Selection<SVGGElement, unknown, null, undefined>;
  private opts: ForceGraphOptions;
  private highlightedPath: Set<string> = new Set();

  constructor(opts: ForceGraphOptions) {
    this.opts = opts;
    this.svg = d3.select(opts.container);

    // Clear existing content
    this.svg.selectAll('*').remove();

    // Zoom container
    this.container = this.svg.append('g');

    this.zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.1, 5])
      .on('zoom', (event) => {
        this.container.attr('transform', event.transform);
      });

    this.svg.call(this.zoom);

    // Arrow markers for edges
    const defs = this.svg.append('defs');
    Object.entries(edgeStyles).forEach(([type, style]) => {
      defs.append('marker')
        .attr('id', `arrow-${type}`)
        .attr('viewBox', '0 -5 10 10')
        .attr('refX', 25)
        .attr('refY', 0)
        .attr('markerWidth', 6)
        .attr('markerHeight', 6)
        .attr('orient', 'auto')
        .append('path')
        .attr('d', 'M0,-5L10,0L0,5')
        .attr('fill', style.color);
    });

    // Groups
    this.linkGroup = this.container.append('g').attr('class', 'links');
    this.nodeGroup = this.container.append('g').attr('class', 'nodes');

    // Simulation
    this.simulation = d3.forceSimulation<GraphNode, GraphLink>()
      .force('charge', d3.forceManyBody().strength(-300))
      .force('link', d3.forceLink<GraphNode, GraphLink>().id(d => d.id).distance(120))
      .force('collision', d3.forceCollide(40))
      .force('center', d3.forceCenter(opts.width / 2, opts.height / 2));
  }

  update(nodes: GraphNode[], links: GraphLink[]) {
    // Links
    const linkSel = this.linkGroup.selectAll<SVGLineElement, GraphLink>('line')
      .data(links, d => d.uuid);

    linkSel.exit().remove();

    const linkEnter = linkSel.enter().append('line');

    const linkMerge = linkEnter.merge(linkSel);
    linkMerge
      .attr('stroke', d => {
        if (this.highlightedPath.has(d.uuid)) return '#FACC15'; // Yellow for path
        return edgeStyles[d.edge_type]?.color || '#6B7280';
      })
      .attr('stroke-width', d => this.highlightedPath.has(d.uuid) ? 3 : 1.5)
      .attr('stroke-dasharray', d => edgeStyles[d.edge_type]?.dash || '')
      .attr('stroke-opacity', d => d.is_stale ? staleOpacity : (edgeStyles[d.edge_type]?.opacity || 1))
      .attr('marker-end', d => `url(#arrow-${d.edge_type})`);

    // Nodes
    const nodeSel = this.nodeGroup.selectAll<SVGGElement, GraphNode>('g')
      .data(nodes, d => d.id);

    nodeSel.exit().remove();

    const nodeEnter = nodeSel.enter().append('g')
      .attr('cursor', 'pointer')
      .call(d3.drag<SVGGElement, GraphNode>()
        .on('start', (event, d) => {
          if (!event.active) this.simulation.alphaTarget(0.3).restart();
          d.fx = d.x;
          d.fy = d.y;
        })
        .on('drag', (event, d) => {
          d.fx = event.x;
          d.fy = event.y;
        })
        .on('end', (event, d) => {
          if (!event.active) this.simulation.alphaTarget(0);
          d.fx = null;
          d.fy = null;
        })
      );

    nodeEnter.append('circle')
      .attr('r', 16)
      .attr('stroke', '#1E293B')
      .attr('stroke-width', 2);

    nodeEnter.append('text')
      .attr('dy', 28)
      .attr('text-anchor', 'middle')
      .attr('fill', '#94A3B8')
      .attr('font-size', '10px')
      .attr('font-family', 'monospace');

    const nodeMerge = nodeEnter.merge(nodeSel);

    nodeMerge.select('circle')
      .attr('fill', d => nodeColors[d.type] || nodeColors.unknown);

    nodeMerge.select('text')
      .text(d => d.label.length > 20 ? d.label.slice(0, 17) + '...' : d.label);

    // Events
    nodeMerge
      .on('click', (_event, d) => this.opts.onNodeClick?.(d))
      .on('mouseenter', (event, d) => this.opts.onNodeHover?.(d, event))
      .on('mouseleave', () => this.opts.onNodeHover?.(null));

    // Update simulation
    this.simulation.nodes(nodes);
    (this.simulation.force('link') as d3.ForceLink<GraphNode, GraphLink>).links(links);
    this.simulation.alpha(1).restart();

    this.simulation.on('tick', () => {
      linkMerge
        .attr('x1', d => (d.source as GraphNode).x!)
        .attr('y1', d => (d.source as GraphNode).y!)
        .attr('x2', d => (d.target as GraphNode).x!)
        .attr('y2', d => (d.target as GraphNode).y!);

      nodeMerge
        .attr('transform', d => `translate(${d.x},${d.y})`);
    });
  }

  highlightPath(edgeUUIDs: string[]) {
    this.highlightedPath = new Set(edgeUUIDs);
    // Re-render edges
    this.linkGroup.selectAll<SVGLineElement, GraphLink>('line')
      .attr('stroke', d => {
        if (this.highlightedPath.has(d.uuid)) return '#FACC15';
        return edgeStyles[d.edge_type]?.color || '#6B7280';
      })
      .attr('stroke-width', d => this.highlightedPath.has(d.uuid) ? 3 : 1.5)
      .attr('stroke-dasharray', d => {
        if (this.highlightedPath.has(d.uuid)) return '8,4';
        return edgeStyles[d.edge_type]?.dash || '';
      });
  }

  clearHighlight() {
    this.highlightedPath.clear();
    this.linkGroup.selectAll<SVGLineElement, GraphLink>('line')
      .attr('stroke', d => edgeStyles[d.edge_type]?.color || '#6B7280')
      .attr('stroke-width', 1.5)
      .attr('stroke-dasharray', d => edgeStyles[d.edge_type]?.dash || '');
  }

  destroy() {
    this.simulation.stop();
    this.svg.selectAll('*').remove();
  }
}
