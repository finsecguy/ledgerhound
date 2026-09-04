import { fireEvent, render, screen } from "@testing-library/react";
import { forwardRef } from "react";
import { describe, expect, it, vi } from "vitest";

import type { CampaignGraph } from "../api/client";

// react-force-graph-2d renders onto an HTML canvas and runs a d3-force
// simulation — not something jsdom can meaningfully execute in a unit
// test. Mocked here so we can test *our* click-handling/data-mapping
// code (EntityGraph's actual responsibility) without needing a real
// canvas or force layout: the mock exposes one button per node/link
// that invokes the exact same onNodeClick/onLinkClick props EntityGraph
// passed to the real component.
vi.mock("react-force-graph-2d", () => ({
  default: forwardRef<
    unknown,
    {
      graphData: { nodes: Array<Record<string, unknown>>; links: Array<Record<string, unknown>> };
      onNodeClick?: (node: unknown, event: unknown) => void;
      onLinkClick?: (link: unknown, event: unknown) => void;
    }
  >((props, _ref) => (
    <div data-testid="mock-force-graph">
      {props.graphData.nodes.map((node) => (
        <button
          key={String(node["id"])}
          data-testid={`mock-node-${String(node["id"])}`}
          onClick={(event) => props.onNodeClick?.(node, event)}
        >
          node
        </button>
      ))}
      {props.graphData.links.map((link, index) => (
        <button
          key={index}
          data-testid={`mock-link-${index}`}
          onClick={(event) => props.onLinkClick?.(link, event)}
        >
          link
        </button>
      ))}
    </div>
  )),
}));

import EntityGraph from "./EntityGraph";

const GRAPH: CampaignGraph = {
  nodes: [
    { id: "member:a", type: "eth_address", value: "0xA", labels: [] },
    { id: "member:b", type: "eth_address", value: "0xB", labels: [] },
  ],
  edges: [
    {
      source: "member:a",
      target: "member:b",
      relation: "shares_receiving_wallet",
      weight: 1,
      evidence: { wallet: "0xW" },
    },
  ],
};

describe("EntityGraph", () => {
  it("calls onNodeSelect with the clicked node's data", () => {
    const onNodeSelect = vi.fn();
    render(<EntityGraph graph={GRAPH} onNodeSelect={onNodeSelect} onEdgeSelect={vi.fn()} />);

    fireEvent.click(screen.getByTestId("mock-node-member:a"));

    expect(onNodeSelect).toHaveBeenCalledTimes(1);
    expect(onNodeSelect.mock.calls[0]?.[0]).toMatchObject({
      id: "member:a",
      type: "eth_address",
      value: "0xA",
    });
  });

  it("calls onEdgeSelect with the clicked edge's data", () => {
    const onEdgeSelect = vi.fn();
    render(<EntityGraph graph={GRAPH} onNodeSelect={vi.fn()} onEdgeSelect={onEdgeSelect} />);

    fireEvent.click(screen.getByTestId("mock-link-0"));

    expect(onEdgeSelect).toHaveBeenCalledTimes(1);
    expect(onEdgeSelect.mock.calls[0]?.[0]).toMatchObject({
      relation: "shares_receiving_wallet",
      weight: 1,
      evidence: { wallet: "0xW" },
    });
  });

  it("does not select anything until a node or edge is clicked", () => {
    const onNodeSelect = vi.fn();
    const onEdgeSelect = vi.fn();
    render(<EntityGraph graph={GRAPH} onNodeSelect={onNodeSelect} onEdgeSelect={onEdgeSelect} />);

    expect(onNodeSelect).not.toHaveBeenCalled();
    expect(onEdgeSelect).not.toHaveBeenCalled();
  });
});
