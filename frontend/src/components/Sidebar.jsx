import { useEffect, useState } from "react";
import { Play, History, Target, Database } from "lucide-react";
import { Input } from "@/components/ui/input";
import { fmtTime, shortGuid } from "@/lib/api";

const Section = ({ title, icon: Icon, children, testid }) => (
  <section data-testid={testid} className="border-b border-white/10 px-4 py-4 flex flex-col gap-3">
    <div className="flex items-center gap-2 text-[10px] font-bold uppercase tracking-[0.2em] text-neutral-500">
      <Icon className="w-3 h-3" /> {title}
    </div>
    {children}
  </section>
);

const fieldCls = "h-8 rounded-none bg-neutral-900 border-white/10 font-mono text-[11px] focus-visible:ring-1 focus-visible:ring-cyan-500 focus-visible:ring-offset-0";

const QueryForm = ({ query, onRun, loading }) => {
  const [form, setForm] = useState(query);
  useEffect(() => setForm(query), [query]);
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });
  return (
    <Section title="Investigation Query" icon={Target} testid="query-section">
      <form
        className="flex flex-col gap-2.5"
        onSubmit={(e) => { e.preventDefault(); form.process_guid && onRun(form); }}
      >
        <label className="text-[10px] font-mono text-neutral-500">TargetProcessGuid</label>
        <Input data-testid="query-process-guid-input" value={form.process_guid} onChange={set("process_guid")} className={fieldCls} />
        <label className="text-[10px] font-mono text-neutral-500">Time window (UTC, ISO-8601)</label>
        <Input data-testid="query-start-time-input" value={form.start_time || ""} onChange={set("start_time")} placeholder="start" className={fieldCls} />
        <Input data-testid="query-end-time-input" value={form.end_time || ""} onChange={set("end_time")} placeholder="end" className={fieldCls} />
        <button
          type="submit"
          data-testid="query-run-btn"
          disabled={loading}
          className="mt-1 h-9 flex items-center justify-center gap-2 bg-cyan-400 text-neutral-950 font-mono text-xs font-bold uppercase tracking-[0.15em] hover:bg-cyan-300 disabled:opacity-50 transition-colors duration-200"
        >
          <Play className="w-3.5 h-3.5" /> Build Graph
        </button>
      </form>
    </Section>
  );
};

const Stat = ({ label, value, accent = "text-neutral-100", testid }) => (
  <div className="border border-white/5 bg-white/[0.02] px-2.5 py-2">
    <div className="text-[9px] font-mono uppercase tracking-[0.15em] text-neutral-500">{label}</div>
    <div data-testid={testid} className={`font-heading text-lg font-bold ${accent}`}>{value}</div>
  </div>
);

const Metadata = ({ meta }) => (
  <Section title="Graph Metadata" icon={Database} testid="metadata-section">
    {meta ? (
      <div className="grid grid-cols-3 gap-1.5">
        <Stat label="Nodes" value={meta.node_count} testid="meta-node-count" />
        <Stat label="Edges" value={meta.edge_count} testid="meta-edge-count" />
        <Stat label="Events" value={meta.events_scanned} testid="meta-events-scanned" />
        <Stat label="Proc" value={meta.process_count} accent="text-slate-300" testid="meta-process-count" />
        <Stat label="Net" value={meta.network_count} accent="text-cyan-300" testid="meta-network-count" />
        <Stat label="File" value={meta.file_count} accent="text-amber-300" testid="meta-file-count" />
        <Stat label="Depth ↑" value={meta.ancestor_depth} testid="meta-ancestor-depth" />
        <Stat label="Depth ↓" value={meta.descendant_depth} testid="meta-descendant-depth" />
        <Stat label="Build ms" value={meta.build_ms} accent="text-emerald-400" testid="meta-build-ms" />
      </div>
    ) : (
      <span className="text-xs font-mono text-neutral-500">No graph built.</span>
    )}
  </Section>
);

const TargetList = ({ items, activeGuid, onPick, testPrefix, render }) => (
  <div className="flex flex-col gap-1">
    {items.map((it, i) => (
      <button
        key={it.id || it.process_guid}
        data-testid={`${testPrefix}-${i}`}
        onClick={() => onPick(it.process_guid)}
        className={`text-left px-2.5 py-2 border transition-colors duration-200 ${
          activeGuid === it.process_guid ? "border-cyan-500/50 bg-cyan-500/[0.07]" : "border-white/5 hover:border-white/15 hover:bg-white/[0.04]"
        }`}
      >
        {render(it)}
      </button>
    ))}
  </div>
);

export const Sidebar = ({ query, onRun, loading, meta, suggested, investigations }) => (
  <aside data-testid="sidebar" className="w-80 shrink-0 border-r border-white/10 bg-neutral-950 overflow-y-auto">
    <QueryForm query={query} onRun={onRun} loading={loading} />
    <Metadata meta={meta} />
    <Section title="Suggested Targets" icon={Target} testid="suggested-section">
      <TargetList
        items={suggested}
        activeGuid={query.process_guid}
        onPick={(g) => onRun({ ...query, process_guid: g })}
        testPrefix="suggested-target"
        render={(t) => (
          <>
            <div className="font-mono text-xs font-semibold text-neutral-100">{t.label}</div>
            <div className="text-[11px] text-neutral-500 mt-0.5">{t.note}</div>
          </>
        )}
      />
    </Section>
    <Section title="Recent Investigations" icon={History} testid="recent-section">
      {investigations.length ? (
        <TargetList
          items={investigations}
          activeGuid={null}
          onPick={(g) => onRun({ ...query, process_guid: g })}
          testPrefix="recent-investigation"
          render={(inv) => (
            <>
              <div className="flex justify-between font-mono text-xs">
                <span className="font-semibold text-neutral-100">{inv.target_image}</span>
                <span className="text-neutral-500">{inv.node_count}n/{inv.edge_count}e</span>
              </div>
              <div className="font-mono text-[10px] text-neutral-500 mt-0.5">
                {shortGuid(inv.process_guid)} · {fmtTime(inv.created_at).slice(0, 19)}
              </div>
            </>
          )}
        />
      ) : (
        <span className="text-xs font-mono text-neutral-500">Run a query to save an investigation.</span>
      )}
    </Section>
  </aside>
);
