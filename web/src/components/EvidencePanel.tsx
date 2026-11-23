import type { ExplainOut, GraphEdge, GraphNode } from "../api/client";

export type GraphSelection =
  | { kind: "node"; node: GraphNode; explain?: ExplainOut }
  | { kind: "edge"; edge: GraphEdge }
  | null;

interface EvidencePanelProps {
  selection: GraphSelection;
  onClose: () => void;
}

function renderEvidenceValue(value: unknown): string {
  if (value === null || value === undefined) {
    return "-";
  }
  if (typeof value === "object") {
    return JSON.stringify(value);
  }
  return String(value);
}

/** Renders the structured evidence for a selected graph node or edge
 * readably, a labeled table of fields, never a raw JSON blob. */
export default function EvidencePanel({ selection, onClose }: EvidencePanelProps): React.JSX.Element {
  if (!selection) {
    return (
      <div className="evidence-dock stack">
        <p className="evidence-dock__empty">Select a node or edge in the graph to inspect its evidence.</p>
      </div>
    );
  }

  if (selection.kind === "edge") {
    const { edge } = selection;
    return (
      <div className="evidence-dock stack" data-testid="evidence-panel-edge">
        <div className="row row--between">
          <h3 className="mono">{edge.relation}</h3>
          <button type="button" className="ghost" onClick={onClose}>
            Close
          </button>
        </div>
        <p>
          Weight: <strong>{edge.weight.toFixed(2)}</strong>
        </p>
        <table className="data-table">
          <tbody>
            {Object.entries(edge.evidence).map(([key, value]) => (
              <tr key={key}>
                <th className="mono">{key}</th>
                <td className="mono">{renderEvidenceValue(value)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  const { node, explain } = selection;
  return (
    <div className="evidence-dock stack" data-testid="evidence-panel-node">
      <div className="row row--between">
        <h3 className="mono">{node.value}</h3>
        <button type="button" className="ghost" onClick={onClose}>
          Close
        </button>
      </div>
      <p className="page-subtitle">{node.type}</p>
      {node.labels.length > 0 && (
        <div className="row">
          {node.labels.map((label, index) => (
            <span key={index} className="badge badge--stale">
              {String(label["label"] ?? label["label_type"] ?? "label")}
            </span>
          ))}
        </div>
      )}
      {explain && explain.direct_edges.length > 0 && (
        <>
          <h4>Direct connections</h4>
          <table className="data-table">
            <thead>
              <tr>
                <th>Neighbor</th>
                <th>Relation</th>
                <th>Weight</th>
              </tr>
            </thead>
            <tbody>
              {explain.direct_edges.map((edge, index) => (
                <tr key={index}>
                  <td className="mono">{edge.neighbor_value ?? edge.neighbor_id}</td>
                  <td>{edge.relation}</td>
                  <td>{edge.weight.toFixed(2)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
      {explain?.path_to_reference && (
        <p className="page-subtitle mono">
          Path to reference member: {explain.path_to_reference.join(" → ")}
        </p>
      )}
    </div>
  );
}

