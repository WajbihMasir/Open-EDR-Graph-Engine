import { useEffect, useMemo, useState } from "react";
import { ReactFlow, Background, Controls, MiniMap, useNodesState } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { ArrowDownUp, ArrowLeftRight, Loader2 } from "lucide-react";
import { nodeTypes } from "./Nodes";
import { layoutGraph, toFlowEdges, EDGE_COLOR } from "./layout";

const MINI_COLOR = { process: "#64748b", network: "#22d3ee", file: "#fbbf24" };

const Legend = () => (
  <div data-testid="graph-legend" className="absolute top-3 left-3 z-10 bg-neutral-950/90 backdrop-blur-xl border border-white/10 px-3 py-2 font-mono text-[10px] text-neutral-400 space-y-1">
    <div className="text-[9px] uppercase tracking-[0.2em] text-neutral-500 mb-1">Edges</div>
    {Object.entries(EDGE_COLOR).map(([k, c]) => (
      <div key={k} className="flex items-center gap-2">
        <span className="w-4 h-px" style={{ background: c }} />
        {k}
      </div>
    ))}
    <div className="text-[9px] uppercase tracking-[0.2em] text-neutral-500 pt-1">Severity</div>
    <div className="flex gap-2">
      {[["critical", "bg-red-500"], ["high", "bg-orange-500"], ["medium", "bg-amber-400"], ["low", "bg-emerald-500"]].map(([k, c]) => (
        <span key={k} className="flex items-center gap-1"><span className={`w-1.5 h-1.5 ${c}`} />{k}</span>
      ))}
    </div>
  </div>
);

export const GraphCanvas = ({ graph, selectedId, onSelect, onPivot, loading }) => {
  const [dir, setDir] = useState("TB");
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const laid = useMemo(() => (graph ? layoutGraph(graph, dir) : []), [graph, dir]);
  const edges = useMemo(() => (graph ? toFlowEdges(graph.edges, selectedId) : []), [graph, selectedId]);

  useEffect(() => {
    setNodes(laid.map((n) => ({ ...n, data: { ...n.data, isSelected: n.id === selectedId } })));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [laid, setNodes]);

  useEffect(() => {
    setNodes((ns) => ns.map((n) => ({ ...n, data: { ...n.data, isSelected: n.id === selectedId } })));
  }, [selectedId, setNodes]);

  const flowKey = graph ? `${graph.metadata.target_node_id}-${graph.metadata.start_time}-${graph.metadata.end_time}-${dir}` : "empty";

  return (
    <div data-testid="graph-canvas" className="flex-1 relative bg-[#070708] min-w-0">
      <Legend />
      <div className="absolute top-3 right-3 z-10 flex border border-white/10 bg-neutral-950/90 backdrop-blur-xl">
        {[["TB", ArrowDownUp, "Top-down"], ["LR", ArrowLeftRight, "Left-right"]].map(([d, Icon, label]) => (
          <button
            key={d}
            data-testid={`layout-${d.toLowerCase()}-btn`}
            onClick={() => setDir(d)}
            className={`flex items-center gap-1.5 px-3 py-1.5 font-mono text-[11px] transition-colors duration-200 ${
              dir === d ? "bg-cyan-500/15 text-cyan-300" : "text-neutral-400 hover:text-neutral-100 hover:bg-white/5"
            }`}
          >
            <Icon className="w-3 h-3" /> {label}
          </button>
        ))}
      </div>
      {loading && (
        <div data-testid="graph-loading" className="absolute inset-0 z-20 flex items-center justify-center bg-black/50">
          <div className="flex items-center gap-2 font-mono text-xs text-cyan-300 border border-cyan-500/30 bg-neutral-950 px-4 py-2">
            <Loader2 className="w-3.5 h-3.5 animate-spin" /> reconstructing process graph…
          </div>
        </div>
      )}
      <ReactFlow
        key={flowKey}
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onNodesChange={onNodesChange}
        onNodeClick={(_, n) => onSelect(n.id)}
        onNodeDoubleClick={(_, n) => n.type === "process" && onPivot(n.data.process_guid)}
        onPaneClick={() => onSelect(null)}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        minZoom={0.15}
        maxZoom={2}
        proOptions={{ hideAttribution: true }}
        colorMode="dark"
      >
        <Background variant="lines" gap={32} color="#16161a" />
        <Controls showInteractive={false} position="bottom-left" />
        <MiniMap
          position="bottom-right"
          pannable
          zoomable
          nodeColor={(n) => (n.data?.role === "target" ? "#ef4444" : MINI_COLOR[n.type])}
          maskColor="rgba(7,7,8,0.75)"
          style={{ background: "#0d0d10", border: "1px solid rgba(255,255,255,0.08)", width: 160, height: 100 }}
        />
      </ReactFlow>
    </div>
  );
};
