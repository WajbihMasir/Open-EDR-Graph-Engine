import { useEffect, useRef, useState } from "react";
import { Search, Loader2 } from "lucide-react";
import { Input } from "@/components/ui/input";
import { api, fmtTime, shortGuid } from "@/lib/api";

export const SearchBar = ({ onPick }) => {
  const [q, setQ] = useState("");
  const [results, setResults] = useState([]);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    if (!q.trim()) return setResults([]);
    setBusy(true);
    const t = setTimeout(() => {
      api.search(q.trim()).then(setResults).finally(() => setBusy(false));
    }, 250);
    return () => clearTimeout(t);
  }, [q]);

  useEffect(() => {
    const close = (e) => ref.current && !ref.current.contains(e.target) && setOpen(false);
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, []);

  const pick = (r) => {
    onPick(r.process_guid);
    setOpen(false);
    setQ("");
  };

  return (
    <div ref={ref} className="relative w-[440px]">
      <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-neutral-500" />
      <Input
        data-testid="search-input"
        value={q}
        onChange={(e) => { setQ(e.target.value); setOpen(true); }}
        onFocus={() => setOpen(true)}
        onKeyDown={(e) => e.key === "Escape" && setOpen(false)}
        placeholder="Search ProcessGuid, PID, image or command line…"
        className="h-9 pl-9 rounded-none bg-neutral-900 border-white/10 font-mono text-xs focus-visible:ring-1 focus-visible:ring-cyan-500 focus-visible:ring-offset-0"
      />
      {busy && <Loader2 className="absolute right-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 animate-spin text-neutral-500" />}
      {open && q.trim() && (
        <div data-testid="search-results" className="absolute top-full mt-1 left-0 right-0 z-50 bg-neutral-950 border border-white/10 max-h-80 overflow-y-auto">
          {!busy && !results.length && <div className="px-3 py-2.5 text-xs font-mono text-neutral-500">No process matches.</div>}
          {results.map((r) => (
            <button
              key={r.process_guid}
              data-testid={`search-result-${r.pid}`}
              onClick={() => pick(r)}
              className="w-full text-left px-3 py-2 border-b border-white/5 hover:bg-cyan-500/10 transition-colors duration-150"
            >
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs font-semibold text-neutral-100">{r.image_name}</span>
                <span className="font-mono text-[10px] text-neutral-500">PID {r.pid}</span>
              </div>
              <div className="font-mono text-[10px] text-neutral-500 mt-0.5">
                {shortGuid(r.process_guid)} · {fmtTime(r.timestamp)} · {r.user}
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
};
