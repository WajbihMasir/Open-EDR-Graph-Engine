import dagre from "@dagrejs/dagre";
import { MarkerType } from "@xyflow/react";

export const NODE_SIZE = {
  process: { w: 248, h: 84 },
  network: { w: 216, h: 60 },
  file: { w: 232, h: 60 },
};

export const EDGE_COLOR = {
  SPAWNED: "#94a3b8",
  CONNECTED_TO: "#22d3ee",
  WROTE_FILE: "#fbbf24",
};

export function layoutGraph(graph, dir) {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: dir, nodesep: 36, ranksep: 80, marginx: 40, marginy: 40 });
  graph.nodes.forEach((n) => g.setNode(n.id, { width: NODE_SIZE[n.type].w, height: NODE_SIZE[n.type].h }));
  graph.edges.forEach((e) => g.setEdge(e.source, e.target));
  dagre.layout(g);
  return graph.nodes.map((n) => {
    const p = g.node(n.id);
    const { w, h } = NODE_SIZE[n.type];
    return { id: n.id, type: n.type, data: { ...n.data, dir }, position: { x: p.x - w / 2, y: p.y - h / 2 } };
  });
}

export function toFlowEdges(edges, selectedId) {
  return edges.map((e) => {
    const active = selectedId && (e.source === selectedId || e.target === selectedId);
    const color = EDGE_COLOR[e.type];
    return {
      id: e.id,
      source: e.source,
      target: e.target,
      type: "smoothstep",
      label: e.type,
      animated: e.type !== "SPAWNED",
      style: { stroke: color, strokeWidth: active ? 2.25 : 1.25, opacity: selectedId && !active ? 0.35 : 1 },
      markerEnd: { type: MarkerType.ArrowClosed, color, width: 16, height: 16 },
      labelStyle: { fill: color, fontSize: 9, fontFamily: "JetBrains Mono, monospace", letterSpacing: "0.08em" },
      labelBgStyle: { fill: "#0a0a0b" },
      labelBgPadding: [4, 2],
    };
  });
}
