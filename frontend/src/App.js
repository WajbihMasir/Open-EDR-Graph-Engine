import { useCallback, useEffect, useMemo, useState } from "react";
import "@/App.css";
import { Network } from "lucide-react";
import { Toaster, toast } from "@/components/ui/sonner";
import { api, fmtTime } from "@/lib/api";
import { GraphCanvas } from "@/components/graph/GraphCanvas";
import { Inspector } from "@/components/Inspector";
import { Sidebar } from "@/components/Sidebar";
import { SearchBar } from "@/components/SearchBar";

const Header = ({ summary, onPick }) => (
  <header data-testid="app-header" className="h-14 shrink-0 border-b border-white/10 flex items-center justify-between px-4 bg-neutral-950/95 backdrop-blur-xl z-50">
    <div className="flex items-center gap-3">
      <div className="w-8 h-8 border border-cyan-400/60 flex items-center justify-center bg-cyan-400/10">
        <Network className="w-4 h-4 text-cyan-300" />
      </div>
      <div>
        <h1 data-testid="app-title" className="font-heading text-base font-bold tracking-tight leading-none">
          Open-EDR <span className="text-cyan-300">Graph Engine</span>
        </h1>
        <div className="text-[10px] font-mono text-neutral-500 mt-1 tracking-[0.15em] uppercase">Sysmon → DAG · Wazuh / OpenSearch</div>
      </div>
    </div>
    <SearchBar onPick={onPick} />
    <div data-testid="telemetry-status" className="flex items-center gap-4 font-mono text-[11px] text-neutral-400">
      {summary && ["1", "3", "11"].map((id) => (
        <span key={id}>EID {id}: <span className="text-neutral-100">{summary.by_event_id[id] || 0}</span></span>
      ))}
      <span className="flex items-center gap-1.5 text-emerald-400"><span className="w-1.5 h-1.5 bg-emerald-400 animate-pulse" /> engine online</span>
    </div>
  </header>
);

const StatusBar = ({ meta, error }) => (
  <footer data-testid="status-bar" className="h-8 shrink-0 border-t border-white/10 bg-neutral-950 flex items-center gap-5 px-4 font-mono text-[10px] text-neutral-500">
    {error ? (
      <span data-testid="status-error" className="text-red-400">ERROR · {error}</span>
    ) : meta ? (
      <>
        <span>target <span className="text-red-300">{meta.target_image}</span></span>
        <span>host <span className="text-neutral-300">{meta.computer}</span></span>
        <span>window <span className="text-neutral-300">{fmtTime(meta.start_time)} → {fmtTime(meta.end_time)}</span></span>
        <span>resolver <span className="text-cyan-300">{meta.resolver}</span></span>
        <span>root parent {meta.root_parent_resolved ? "resolved" : <span className="text-amber-300">outside telemetry</span>}</span>
      </>
    ) : (
      <span>idle</span>
    )}
  </footer>
);

export default function App() {
  const [summary, setSummary] = useState(null);
  const [query, setQuery] = useState({ process_guid: "", start_time: "", end_time: "" });
  const [graph, setGraph] = useState(null);
  const [selectedId, setSelectedId] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [investigations, setInvestigations] = useState([]);

  const refreshInvestigations = useCallback(() => api.investigations().then(setInvestigations), []);

  const run = useCallback(async (q, persist = true) => {
    setLoading(true);
    setError(null);
    try {
      const data = persist ? (await api.investigate(q)).graph : await api.graph(q);
      setGraph(data);
      setQuery(q);
      setSelectedId(data.metadata.target_node_id);
      if (persist) refreshInvestigations();
    } catch (e) {
      const msg = e.response?.data?.detail || "Graph build failed";
      setError(msg);
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  }, [refreshInvestigations]);

  useEffect(() => {
    api.summary().then((s) => {
      setSummary(s);
      run({ process_guid: s.default_target, start_time: s.time_range.start, end_time: s.time_range.end }, false);
    });
    refreshInvestigations();
  }, [run, refreshInvestigations]);

  const selected = useMemo(() => graph?.nodes.find((n) => n.id === selectedId) || null, [graph, selectedId]);
  const pivot = useCallback((guid) => run({ ...query, process_guid: guid }), [run, query]);

  return (
    <div className="h-screen w-screen flex flex-col overflow-hidden bg-[#0a0a0b] text-neutral-50 font-body">
      <Header summary={summary} onPick={pivot} />
      <main className="flex-1 flex overflow-hidden">
        <Sidebar
          query={query}
          onRun={run}
          loading={loading}
          meta={graph?.metadata}
          suggested={summary?.suggested_targets || []}
          investigations={investigations}
        />
        <GraphCanvas graph={graph} selectedId={selectedId} onSelect={setSelectedId} onPivot={pivot} loading={loading} />
        <Inspector node={selected} graph={graph} onSelect={setSelectedId} onPivot={pivot} />
      </main>
      <StatusBar meta={graph?.metadata} error={error} />
      <Toaster theme="dark" position="bottom-right" />
    </div>
  );
}
