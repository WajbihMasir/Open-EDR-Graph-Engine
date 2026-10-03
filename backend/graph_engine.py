"""Open-EDR Graph Builder: Sysmon events (EID 1/3/11) -> process DAG (nodes + edges)."""
import base64
import ipaddress
import re
import time
from collections import defaultdict, deque

EID_PROCESS, EID_NETWORK, EID_FILE = 1, 3, 11
OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
SHELLS = {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
RISKY_EXT = {"exe", "dll", "ps1", "vbs", "js", "bat", "hta", "scr"}


def basename(path):
    return re.split(r"[\\/]", path or "")[-1] or (path or "")


def dirname(path):
    parts = re.split(r"[\\/]", path or "")
    return "\\".join(parts[:-1])


def parse_hashes(raw):
    out = {}
    for part in (raw or "").split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip()
    return out


def decode_command(cmd):
    m = re.search(r"\s-(?:e|ec|enc|encodedcommand)\s+([A-Za-z0-9+/=]{8,})", cmd or "", re.I)
    if not m:
        return None
    try:
        return base64.b64decode(m.group(1)).decode("utf-16-le")
    except Exception:
        return None


def is_external(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local)
    except ValueError:
        return False


def parse_event(raw):
    """Sysmon Event Parser: normalise a raw Wazuh/Sysmon document."""
    eid = int(raw.get("event_id", 0))
    d = raw.get("event_data", {})
    base = {"event_id": eid, "timestamp": raw.get("timestamp"), "computer": raw.get("computer")}
    if eid == EID_PROCESS:
        image = d.get("Image", "")
        cmd = d.get("CommandLine", "")
        return {**base, "kind": "process",
                "process_guid": d.get("ProcessGuid"), "parent_process_guid": d.get("ParentProcessGuid"),
                "pid": d.get("ProcessId"), "parent_pid": d.get("ParentProcessId"),
                "image_name": basename(image), "full_path": image,
                "parent_image": d.get("ParentImage", ""), "command_line": cmd,
                "decoded_command": decode_command(cmd), "user": d.get("User"),
                "integrity_level": d.get("IntegrityLevel"), "hashes": parse_hashes(d.get("Hashes"))}
    if eid == EID_NETWORK:
        return {**base, "kind": "network", "process_guid": d.get("ProcessGuid"),
                "destination_ip": d.get("DestinationIp"), "destination_port": d.get("DestinationPort"),
                "destination_hostname": d.get("DestinationHostname") or None,
                "protocol": d.get("Protocol", "tcp"), "source_ip": d.get("SourceIp"),
                "source_port": d.get("SourcePort")}
    if eid == EID_FILE:
        target = d.get("TargetFilename", "")
        name = basename(target)
        return {**base, "kind": "file", "process_guid": d.get("ProcessGuid"),
                "target_filename": target, "file_name": name,
                "file_extension": name.rsplit(".", 1)[-1].lower() if "." in name else "",
                "directory_path": dirname(target)}
    return None


def map_mitre(proc, parent_image):
    img, path = proc["image_name"].lower(), proc["full_path"].lower()
    cmd = proc["command_line"].lower()
    decoded = (proc["decoded_command"] or "").lower()
    parent = basename(parent_image).lower()
    t = []
    if parent in OFFICE and img in SHELLS:
        t.append(("T1566.001", "Spearphishing Attachment", "Initial Access"))
    if img == "cmd.exe":
        t.append(("T1059.003", "Windows Command Shell", "Execution"))
    if img == "powershell.exe":
        t.append(("T1059.001", "PowerShell", "Execution"))
    if proc["decoded_command"] or " -enc" in cmd:
        t.append(("T1027", "Obfuscated Files or Information", "Defense Evasion"))
    if img == "curl.exe" or "downloadfile" in decoded or "invoke-webrequest" in decoded:
        t.append(("T1105", "Ingress Tool Transfer", "Command and Control"))
    if img == "rundll32.exe":
        t.append(("T1218.011", "Rundll32", "Defense Evasion"))
    if "\\users\\public\\" in path or "\\appdata\\local\\temp\\" in path:
        t.append(("T1204.002", "Malicious File", "Execution"))
    if img == "whoami.exe":
        t.append(("T1033", "System Owner/User Discovery", "Discovery"))
    return [{"technique_id": a, "name": b, "tactic": c} for a, b, c in t]


def process_severity(proc, mitre):
    ids = {m["technique_id"] for m in mitre}
    if ids & {"T1204.002", "T1218.011", "T1027"}:
        return "critical"
    if mitre:
        return "high"
    if proc["image_name"].lower() in OFFICE:
        return "medium"
    return "low"


def build_graph(raw_events, target_guid):
    """Resolve identity by ProcessGuid, traverse ancestors/descendants, correlate artifacts."""
    t0 = time.perf_counter()
    procs, children = {}, defaultdict(list)
    net_by, file_by = defaultdict(list), defaultdict(list)
    for raw in raw_events:  # order-independent: all events indexed before resolution
        ev = parse_event(raw)
        if not ev or not ev.get("process_guid"):
            continue
        if ev["kind"] == "process":
            procs[ev["process_guid"]] = ev
        elif ev["kind"] == "network":
            net_by[ev["process_guid"]].append(ev)
        else:
            file_by[ev["process_guid"]].append(ev)
    for p in procs.values():
        children[p["parent_process_guid"]].append(p["process_guid"])

    if target_guid not in procs:
        return None

    ancestors, seen = [], {target_guid}
    cur = procs[target_guid]["parent_process_guid"]
    while cur in procs and cur not in seen:
        ancestors.append(cur)
        seen.add(cur)
        cur = procs[cur]["parent_process_guid"]

    descendants, max_down = {}, 0
    queue = deque((c, 1) for c in children[target_guid])
    while queue:
        guid, depth = queue.popleft()
        if guid in seen:
            continue
        seen.add(guid)
        descendants[guid] = depth
        max_down = max(max_down, depth)
        queue.extend((c, depth + 1) for c in children[guid])

    roles = {g: "ancestor" for g in reversed(ancestors)}
    roles[target_guid] = "target"
    roles.update({g: "descendant" for g in descendants})

    nodes, edges, node_ids, edge_ids = [], [], set(), set()

    def add_edge(etype, src, dst, ts):
        eid = f"{etype}:{src}->{dst}"
        if eid not in edge_ids:
            edge_ids.add(eid)
            edges.append({"id": eid, "source": src, "target": dst, "type": etype, "timestamp": ts})

    for guid, role in roles.items():
        p = procs[guid]
        mitre = map_mitre(p, p["parent_image"])
        nid = f"proc:{guid}"
        nodes.append({"id": nid, "type": "process", "data": {
            **{k: p[k] for k in ("process_guid", "parent_process_guid", "pid", "parent_pid", "image_name",
                                 "full_path", "parent_image", "command_line", "decoded_command", "user",
                                 "integrity_level", "hashes", "computer")},
            "start_time": p["timestamp"], "role": role, "mitre": mitre,
            "severity": process_severity(p, mitre),
            "parent_resolved": p["parent_process_guid"] in procs,
            "child_count": len(children[guid]),
        }})
        node_ids.add(nid)
        if p["parent_process_guid"] in roles:
            add_edge("SPAWNED", f"proc:{p['parent_process_guid']}", nid, p["timestamp"])

    proc_sev = {n["data"]["process_guid"]: n["data"]["severity"] for n in nodes}
    for guid in roles:
        src = f"proc:{guid}"
        for n in net_by[guid]:
            nid = f"net:{n['destination_ip']}:{n['destination_port']}"
            if nid not in node_ids:
                node_ids.add(nid)
                ext = is_external(n["destination_ip"])
                nodes.append({"id": nid, "type": "network", "data": {
                    **{k: n[k] for k in ("destination_ip", "destination_port", "destination_hostname",
                                         "protocol", "source_ip", "source_port")},
                    "first_seen": n["timestamp"], "external": ext,
                    "severity": "high" if ext and proc_sev[guid] in ("high", "critical") else "low"}})
            add_edge("CONNECTED_TO", src, nid, n["timestamp"])
        for f in file_by[guid]:
            nid = f"file:{f['target_filename'].lower()}"
            if nid not in node_ids:
                node_ids.add(nid)
                risky = f["file_extension"] in RISKY_EXT
                nodes.append({"id": nid, "type": "file", "data": {
                    **{k: f[k] for k in ("target_filename", "file_name", "file_extension", "directory_path")},
                    "created_time": f["timestamp"],
                    "severity": "high" if risky else "low"}})
            add_edge("WROTE_FILE", src, nid, f["timestamp"])

    edges.sort(key=lambda e: e["timestamp"] or "")
    counts = defaultdict(int)
    for n in nodes:
        counts[n["type"]] += 1
    target = procs[target_guid]
    return {
        "nodes": nodes,
        "edges": edges,
        "metadata": {
            "target_process_guid": target_guid,
            "target_node_id": f"proc:{target_guid}",
            "target_image": target["image_name"],
            "computer": target["computer"],
            "events_scanned": len(raw_events),
            "node_count": len(nodes),
            "edge_count": len(edges),
            "process_count": counts["process"],
            "network_count": counts["network"],
            "file_count": counts["file"],
            "ancestor_depth": len(ancestors),
            "descendant_depth": max_down,
            "root_parent_guid": cur,
            "root_parent_resolved": cur in procs,
            "resolver": "ProcessGuid",
            "build_ms": round((time.perf_counter() - t0) * 1000, 3),
        },
    }
