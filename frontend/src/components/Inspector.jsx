import { Copy, X, Crosshair, ChevronRight, Unlink } from "lucide-react";
import { toast } from "sonner";
import { fmtTime } from "@/lib/api";

const Label = ({ children }) => (
  <div className="text-[10px] font-bold uppercase tracking-[0.2em] text-neutral-500">{children}</div>
);

const Field = ({ label, value, mono = true, copy, testid }) => (
  <div className="flex flex-col gap-1 min-w-0">
    <Label>{label}</Label>
    <div className="flex items-start gap-2 group">
      <span data-testid={testid} className={`text-sm break-all text-neutral-100 ${mono ? "font-mono" : ""}`}>
        {value ?? "—"}
      </span>
      {copy && value && (
        <button
          data-testid={`${testid}-copy`}
          onClick={() => navigator.clipboard?.writeText(String(value)).then(() => toast.success(`${label} copied`))}
          className="opacity-40 hover:opacity-100 transition-opacity duration-200 mt-0.5"
        >
          <Copy className="w-3 h-3" />
        </button>
      )}
    </div>
  </div>
);

const NodeLink = ({ node, onSelect }) => {
  const d = node.data;
  const label = node.type === "process" ? d.image_name : node.type === "network" ? `${d.destination_ip}:${d.destination_port}` : d.file_name;
  const color = node.type === "process" ? "text-slate-200" : node.type === "network" ? "text-cyan-300" : "text-amber-300";
  return (
    <button
      data-testid={`inspector-link-${node.id}`}
      onClick={() => onSelect(node.id)}
      className={`w-full flex items-center justify-between px-2 py-1.5 border border-white/5 bg-white/[0.02] hover:bg-white/[0.06] hover:border-white/15 transition-colors duration-200 font-mono text-xs ${color}`}
    >
      <span className="truncate">{label}</span>
      <ChevronRight className="w-3 h-3 opacity-50 shrink-0" />
    </button>
  );
};

const Related = ({ title, edges, graph, pick, onSelect }) => {
  const byId = Object.fromEntries(graph.nodes.map((n) => [n.id, n]));
  if (!edges.length) return null;
  return (
    <div className="flex flex-col gap-1.5">
      <Label>{title} ({edges.length})</Label>
      {edges.map((e) => (
        <div key={e.id} className="flex items-center gap-2">
          <span className="text-[9px] font-mono text-neutral-500 w-20 shrink-0">{e.type}</span>
          <NodeLink node={byId[pick(e)]} onSelect={onSelect} />
        </div>
      ))}
    </div>
  );
};

const ProcessBody = ({ d, graph, node, onSelect, onPivot }) => {
  const parentNode = graph.nodes.find((n) => n.id === `proc:${d.parent_process_guid}`);
  const out = graph.edges.filter((e) => e.source === node.id);
  return (
    <>
      <div className="grid grid-cols-2 gap-4">
        <Field label="PID" value={d.pid} testid="inspector-pid" />
        <Field label="Integrity" value={d.integrity_level} testid="inspector-integrity" />
        <Field label="User" value={d.user} testid="inspector-user" />
        <Field label="Start Time" value={fmtTime(d.start_time)} testid="inspector-start-time" />
      </div>
      <Field label="Image Path" value={d.full_path} testid="inspector-image-path" />
      <Field label="Process GUID" value={d.process_guid} copy testid="inspector-process-guid" />
      <div className="flex flex-col gap-1.5">
        <Label>Parent</Label>
        {parentNode ? (
          <NodeLink node={parentNode} onSelect={onSelect} />
        ) : (
          <div data-testid="inspector-parent-unresolved" className="flex items-center gap-2 text-xs font-mono text-neutral-400 border border-dashed border-white/15 px-2 py-1.5">
            <Unlink className="w-3 h-3 text-amber-400" /> {d.parent_image.split("\\").pop()} (PID {d.parent_pid}) · not in window
          </div>
        )}
      </div>
      <div className="flex flex-col gap-1.5">
        <Label>Command Line</Label>
        <pre data-testid="inspector-command-line" className="text-xs font-mono text-neutral-200 bg-black border border-white/10 p-2.5 whitespace-pre-wrap break-all max-h-40 overflow-y-auto">
          {d.command_line}
        </pre>
        {d.decoded_command && (
          <>
            <div className="text-[10px] font-bold uppercase tracking-[0.2em] text-red-400 mt-1">Base64 decoded (-enc)</div>
            <pre data-testid="inspector-decoded-command" className="text-xs font-mono text-red-200 bg-red-950/30 border border-red-500/30 p-2.5 whitespace-pre-wrap break-all">
              {d.decoded_command}
            </pre>
          </>
        )}
      </div>
      <Field label="SHA256" value={d.hashes?.sha256} copy testid="inspector-sha256" />
      <Field label="MD5" value={d.hashes?.md5} testid="inspector-md5" />
      <div className="flex flex-col gap-1.5">
        <Label>MITRE ATT&CK</Label>
        {d.mitre.length ? (
          d.mitre.map((m) => (
            <div key={m.technique_id} data-testid={`inspector-mitre-${m.technique_id}`} className="flex items-center gap-2 border border-red-500/30 bg-red-500/[0.07] px-2 py-1.5">
              <span className="font-mono text-xs font-bold text-red-300">{m.technique_id}</span>
              <span className="text-xs text-neutral-200 truncate">{m.name}</span>
              <span className="ml-auto text-[9px] font-mono uppercase text-neutral-500 shrink-0">{m.tactic}</span>
            </div>
          ))
        ) : (
          <span className="text-xs font-mono text-neutral-500">No technique mapped</span>
        )}
      </div>
      <Related title="Outbound relations" edges={out} graph={graph} pick={(e) => e.target} onSelect={onSelect} />
      {d.role !== "target" && (
        <button
          data-testid="inspector-pivot-btn"
          onClick={() => onPivot(d.process_guid)}
          className="flex items-center justify-center gap-2 py-2 border border-cyan-500/40 text-cyan-300 font-mono text-xs uppercase tracking-[0.15em] hover:bg-cyan-500/10 transition-colors duration-200"
        >
          <Crosshair className="w-3.5 h-3.5" /> Pivot graph to this process
        </button>
      )}
    </>
  );
};

const ArtifactBody = ({ node, graph, onSelect }) => {
  const d = node.data;
  const inbound = graph.edges.filter((e) => e.target === node.id);
  const fields =
    node.type === "network"
      ? [["Destination IP", d.destination_ip, true], ["Port", d.destination_port], ["Protocol", d.protocol?.toUpperCase()],
         ["Hostname", d.destination_hostname], ["Scope", d.external ? "External" : "Internal"], ["First Seen", fmtTime(d.first_seen)]]
      : [["Target Filename", d.target_filename, true], ["Extension", d.file_extension], ["Directory", d.directory_path],
         ["Created", fmtTime(d.created_time)]];
  return (
    <>
      <div className="grid grid-cols-2 gap-4">
        {fields.map(([l, v, copy]) => (
          <div key={l} className={copy || l === "Directory" ? "col-span-2" : ""}>
            <Field label={l} value={v} copy={copy} testid={`inspector-${l.toLowerCase().replace(/\s/g, "-")}`} />
          </div>
        ))}
      </div>
      <Related title={node.type === "network" ? "Initiated by" : "Written by"} edges={inbound} graph={graph} pick={(e) => e.source} onSelect={onSelect} />
    </>
  );
};

const TITLE = { process: "Process Inspector", network: "Network Artifact", file: "File Artifact" };
const SEV = { critical: "text-red-400 border-red-500/50", high: "text-orange-400 border-orange-500/50", medium: "text-amber-300 border-amber-400/50", low: "text-emerald-400 border-emerald-500/50" };

export const Inspector = ({ node, graph, onSelect, onPivot }) => {
  if (!node) {
    return (
      <aside data-testid="inspector-empty" className="w-[400px] shrink-0 border-l border-white/10 bg-neutral-950 p-6 flex flex-col gap-3">
        <Label>Process Inspector</Label>
        <p className="text-sm text-neutral-400 leading-relaxed">
          Click a node on the canvas to inspect its forensic context. Double-click a process to pivot the graph around it.
        </p>
      </aside>
    );
  }
  const d = node.data;
  const title = node.type === "process" ? d.image_name : node.type === "network" ? d.destination_ip : d.file_name;
  return (
    <aside data-testid="inspector-panel" className="w-[400px] shrink-0 border-l border-white/10 bg-neutral-950 overflow-y-auto edr-slide-in">
      <div className="sticky top-0 z-10 bg-neutral-950/95 backdrop-blur-xl border-b border-white/10 px-5 py-4 flex items-start justify-between gap-3">
        <div className="min-w-0">
          <Label>{TITLE[node.type]}</Label>
          <h2 data-testid="inspector-title" className="font-heading text-lg font-bold tracking-tight truncate mt-1">{title}</h2>
          <div className="flex gap-2 mt-2">
            <span data-testid="inspector-severity" className={`text-[10px] font-mono uppercase px-1.5 border ${SEV[d.severity]}`}>{d.severity}</span>
            {d.role && <span className="text-[10px] font-mono uppercase px-1.5 border border-white/15 text-neutral-400">{d.role}</span>}
          </div>
        </div>
        <button data-testid="inspector-close-btn" onClick={() => onSelect(null)} className="p-1 text-neutral-500 hover:text-neutral-100 hover:bg-white/5 transition-colors duration-200">
          <X className="w-4 h-4" />
        </button>
      </div>
      <div className="p-5 flex flex-col gap-5">
        {node.type === "process" ? (
          <ProcessBody d={d} node={node} graph={graph} onSelect={onSelect} onPivot={onPivot} />
        ) : (
          <ArtifactBody node={node} graph={graph} onSelect={onSelect} />
        )}
      </div>
    </aside>
  );
};
