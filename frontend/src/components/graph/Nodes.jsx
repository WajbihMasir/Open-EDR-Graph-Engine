import { memo } from "react";
import { Handle, Position } from "@xyflow/react";
import { Cpu, Globe, FileText, Crosshair } from "lucide-react";
import { slug } from "@/lib/api";

const SEV_BORDER = {
  critical: "border-l-red-500",
  high: "border-l-orange-500",
  medium: "border-l-amber-400",
  low: "border-l-emerald-500",
};
const SEV_TEXT = { critical: "text-red-400", high: "text-orange-400", medium: "text-amber-300", low: "text-emerald-400" };

const Handles = ({ dir }) => {
  const cls = "!w-1.5 !h-1.5 !min-w-0 !min-h-0 !rounded-none !border-0 !bg-neutral-500";
  return (
    <>
      <Handle type="target" position={dir === "LR" ? Position.Left : Position.Top} className={cls} />
      <Handle type="source" position={dir === "LR" ? Position.Right : Position.Bottom} className={cls} />
    </>
  );
};

const shell = (selected) =>
  `relative bg-neutral-900 border border-white/10 border-l-4 px-3 py-2 transition-transform duration-150 hover:scale-[1.03] cursor-pointer ${
    selected ? "outline outline-1 outline-offset-2 outline-cyan-400" : ""
  }`;

export const ProcessNode = memo(({ data }) => {
  const isTarget = data.role === "target";
  return (
    <div
      data-testid={`graph-node-${slug(data.image_name)}-${data.pid}`}
      className={`${shell(data.isSelected)} ${SEV_BORDER[data.severity]} ${isTarget ? "edr-target" : ""}`}
      style={{ width: 248, height: 84 }}
    >
      <Handles dir={data.dir} />
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          {isTarget ? <Crosshair className="w-3.5 h-3.5 text-red-400 shrink-0" /> : <Cpu className="w-3.5 h-3.5 text-slate-400 shrink-0" />}
          <span className="font-heading text-sm font-bold truncate text-neutral-50">{data.image_name}</span>
        </div>
        <span className={`text-[9px] font-mono uppercase tracking-[0.15em] ${isTarget ? "text-red-400" : "text-neutral-500"}`}>
          {data.role}
        </span>
      </div>
      <div className="mt-1 text-[11px] font-mono text-neutral-400 truncate">
        PID {data.pid} · <span className={SEV_TEXT[data.severity]}>{data.severity}</span> · {data.integrity_level}
      </div>
      <div className="mt-1.5 flex gap-1 overflow-hidden">
        {data.mitre.slice(0, 3).map((m) => (
          <span key={m.technique_id} className="text-[9px] font-mono px-1 border border-red-500/40 bg-red-500/10 text-red-300">
            {m.technique_id}
          </span>
        ))}
        {!data.mitre.length && <span className="text-[9px] font-mono text-neutral-600">no technique mapped</span>}
      </div>
    </div>
  );
});

export const NetworkNode = memo(({ data }) => (
  <div
    data-testid={`graph-node-net-${slug(data.destination_ip)}-${data.destination_port}`}
    className={`${shell(data.isSelected)} border-l-cyan-400`}
    style={{ width: 216, height: 60 }}
  >
    <Handles dir={data.dir} />
    <div className="flex items-center gap-2">
      <Globe className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
      <span className="font-mono text-sm font-semibold text-cyan-200 truncate">
        {data.destination_ip}:{data.destination_port}
      </span>
    </div>
    <div className="mt-1 text-[11px] font-mono text-neutral-400 truncate">
      {data.protocol?.toUpperCase()} · {data.destination_hostname || (data.external ? "external" : "internal")}
    </div>
  </div>
));

export const FileNode = memo(({ data }) => (
  <div
    data-testid={`graph-node-file-${slug(data.file_name)}`}
    className={`${shell(data.isSelected)} border-l-amber-400`}
    style={{ width: 232, height: 60 }}
  >
    <Handles dir={data.dir} />
    <div className="flex items-center gap-2">
      <FileText className="w-3.5 h-3.5 text-amber-400 shrink-0" />
      <span className="font-mono text-sm font-semibold text-amber-200 truncate">{data.file_name}</span>
    </div>
    <div className="mt-1 text-[11px] font-mono text-neutral-400 truncate">{data.directory_path}</div>
  </div>
));

export const nodeTypes = { process: ProcessNode, network: NetworkNode, file: FileNode };
