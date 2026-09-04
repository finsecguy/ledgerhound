import { useMemo, useRef } from "react";
import ForceGraph2D, { type ForceGraphMethods } from "react-force-graph-2d";

import type { CampaignGraph, GraphEdge, GraphNode } from "../api/client";

// Colored by indicator type (nodes) and relation type (edges) — a fixed,
// small palette rather than auto-coloring, so the same type always
// reads as the same color across every campaign's graph. Chosen for
// legibility against the warm-ink background (--ink, #161310), not
// matched to the UI's own muted palette — a graph's category colors are
// content, not chrome, so they're allowed more saturation than the rest
// of the app.
const NODE_COLORS: Record<string, string> = {
  btc_address: "#d9b23c",
  eth_address: "#8c7ae6",
  tron_address: "#d9634f",
  sol_address: "#9b59b6",
  domain: "#c78a3d",
  url: "#4f8fd1",
  telegram_handle: "#7a8ba0",
};
const DEFAULT_NODE_COLOR = "#6b6152";

const RELATION_COLORS: Record<string, string> = {
  shares_receiving_wallet: "#c78a3d",
  shares_cashout_path: "#d9b23c",
  shares_cert: "#d9634f",
  shares_template: "#8c7ae6",
  // Corroboration-only relation (see cluster/scoring.py) — deliberately
  // the weakest color here too, matching its weakest evidentiary weight.
  shares_registrar_and_ns: "#6b6152",
};
const DEFAULT_RELATION_COLOR = "#4a4030";

const GRAPH_BACKGROUND = "#161310";

function prefersReducedMotion(): boolean {
  return (
    typeof window !== "undefined" &&
    window.matchMedia?.("(prefers-reduced-motion: reduce)").matches === true
  );
}

interface GraphNodeDatum extends GraphNode {
  x?: number;
  y?: number;
}

interface GraphLinkDatum extends GraphEdge {
  source: string;
  target: string;
}

interface EntityGraphProps {
  graph: CampaignGraph;
  onNodeSelect: (node: GraphNode) => void;
  onEdgeSelect: (edge: GraphEdge) => void;
  height?: number;
}

/** Interactive force-directed entity graph. Nodes colored by indicator
 * type, edge thickness scaled by weight, edge color by relation type.
 * Clicking a node/edge doesn't render evidence itself — it reports the
 * selection up to the caller (`CampaignDetail`), which fetches/renders
 * the actual evidence panel; this component only owns the graph. */
export default function EntityGraph({
  graph,
  onNodeSelect,
  onEdgeSelect,
  height = 560,
}: EntityGraphProps): React.JSX.Element {
  const fgRef = useRef<ForceGraphMethods<GraphNodeDatum, GraphLinkDatum> | undefined>(undefined);

  const data = useMemo(
    () => ({
      nodes: graph.nodes.map((node): GraphNodeDatum => ({ ...node })),
      links: graph.edges.map(
        (edge): GraphLinkDatum => ({ ...edge, source: edge.source, target: edge.target }),
      ),
    }),
    [graph],
  );

  // The graph settling into its force-directed layout is this app's one
  // deliberate motion moment (see theme.css) — reduced-motion viewers
  // get the same final layout without watching it animate there.
  const reducedMotion = useMemo(prefersReducedMotion, []);

  return (
    <div className="entity-graph" data-testid="entity-graph">
      <ForceGraph2D<GraphNodeDatum, GraphLinkDatum>
        ref={fgRef}
        graphData={data}
        height={height}
        backgroundColor={GRAPH_BACKGROUND}
        cooldownTicks={reducedMotion ? 0 : undefined}
        warmupTicks={reducedMotion ? 100 : 0}
        nodeId="id"
        nodeLabel={(node) => `${node.type}: ${node.value}`}
        nodeColor={(node) => NODE_COLORS[node.type] ?? DEFAULT_NODE_COLOR}
        nodeRelSize={5}
        linkLabel={(link) => `${link.relation} (weight ${link.weight.toFixed(2)})`}
        linkColor={(link) => RELATION_COLORS[link.relation] ?? DEFAULT_RELATION_COLOR}
        linkWidth={(link) => 1 + link.weight * 3}
        linkDirectionalParticles={0}
        onNodeClick={(node) => onNodeSelect(node)}
        onLinkClick={(link) => onEdgeSelect(link)}
      />
    </div>
  );
}

export const _internal = { NODE_COLORS, RELATION_COLORS };
