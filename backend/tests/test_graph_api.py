"""Backend tests for Open-EDR Graph Engine (events, graph, investigations, search)."""
import os
from urllib.parse import quote

import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL") or "https://edr-graph-builder.preview.emergentagent.com"
BASE_URL = BASE_URL.rstrip("/")
API = f"{BASE_URL}/api"

PS_GUID = "{6a1f3c2e-2c42-6668-0c01-000000002a00}"
EXPLORER_GUID = "{6a1f3c2e-1a22-6668-0c01-000000002a00}"
SVCHOST_GUID = "{6a1f3c2e-0a03-6668-0c01-000000002a00}"
MALWARE_GUID = "{6a1f3c2e-2c44-6668-0c01-000000002a00}"


def _enc(g):
    return quote(g, safe="")


@pytest.fixture(scope="module")
def session():
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    return s


# ---------- /api/events/summary ----------
def test_summary_totals(session):
    r = session.get(f"{API}/events/summary")
    assert r.status_code == 200
    d = r.json()
    assert d["total"] == 22
    assert d["by_event_id"].get("1") == 12
    assert d["by_event_id"].get("3") == 5
    assert d["by_event_id"].get("11") == 5
    assert d["default_target"] == PS_GUID
    assert isinstance(d["suggested_targets"], list) and len(d["suggested_targets"]) == 5
    labels = {t["label"] for t in d["suggested_targets"]}
    assert {"powershell.exe", "WINWORD.EXE", "malware.exe", "explorer.exe", "svchost.exe"} <= labels


# ---------- /api/graph/{guid} ----------
def test_graph_powershell_target(session):
    r = session.get(f"{API}/graph/{_enc(PS_GUID)}")
    assert r.status_code == 200
    g = r.json()
    m = g["metadata"]
    assert m["node_count"] == 15
    assert m["edge_count"] == 15
    assert m["target_image"] == "powershell.exe"
    assert m["ancestor_depth"] == 3  # explorer -> winword -> cmd
    assert m["resolver"] == "ProcessGuid"

    node_images = [n["data"].get("image_name") for n in g["nodes"] if n["type"] == "process"]
    assert "powershell.exe" in node_images
    for req in ("explorer.exe", "WINWORD.EXE", "cmd.exe", "curl.exe", "malware.exe", "rundll32.exe", "whoami.exe"):
        assert req in node_images, f"missing process {req}"
    for forbidden in ("chrome.exe", "svchost.exe", "services.exe", "taskhostw.exe"):
        assert forbidden not in node_images, f"forbidden process {forbidden} present"

    # network nodes
    net_ids = {(n["data"]["destination_ip"], n["data"]["destination_port"]) for n in g["nodes"] if n["type"] == "network"}
    assert ("185.220.101.47", 443) in net_ids
    assert ("45.137.21.9", 443) in net_ids
    assert ("45.137.21.9", 8080) in net_ids

    # file nodes
    file_names = {n["data"]["file_name"] for n in g["nodes"] if n["type"] == "file"}
    assert {"payload.dll", "malware.exe", "svc_cache.dat", "~WRF0001.tmp"} <= file_names

    # powershell decoded command + MITRE
    ps_node = next(n for n in g["nodes"] if n["type"] == "process" and n["data"]["image_name"] == "powershell.exe")
    assert ps_node["data"]["role"] == "target"
    assert ps_node["data"]["decoded_command"] and "DownloadFile" in ps_node["data"]["decoded_command"]
    mitre_ids = {m["technique_id"] for m in ps_node["data"]["mitre"]}
    assert "T1059.001" in mitre_ids


def test_graph_unknown_guid_404(session):
    r = session.get(f"{API}/graph/{_enc('{00000000-0000-0000-0000-000000000000}')}")
    assert r.status_code == 404


def test_graph_time_window_excludes_target(session):
    # end before 10:21:05 -> powershell proc event excluded -> 404
    r = session.get(f"{API}/graph/{_enc(PS_GUID)}", params={"end_time": "2026-06-10T10:21:04.999Z"})
    assert r.status_code == 404


def test_graph_explorer_includes_chrome(session):
    r = session.get(f"{API}/graph/{_enc(EXPLORER_GUID)}")
    assert r.status_code == 200
    images = [n["data"].get("image_name") for n in r.json()["nodes"] if n["type"] == "process"]
    assert "chrome.exe" in images
    assert "powershell.exe" in images  # descendant


def test_graph_svchost_benign(session):
    r = session.get(f"{API}/graph/{_enc(SVCHOST_GUID)}")
    assert r.status_code == 200
    images = {n["data"].get("image_name") for n in r.json()["nodes"] if n["type"] == "process"}
    assert images == {"services.exe", "svchost.exe", "taskhostw.exe"}


# ---------- /api/investigations ----------
def test_create_and_list_investigation(session):
    r = session.post(f"{API}/investigations", json={"process_guid": PS_GUID})
    assert r.status_code == 200
    body = r.json()
    assert "investigation" in body and "graph" in body
    inv = body["investigation"]
    assert inv["process_guid"] == PS_GUID
    assert inv["target_image"] == "powershell.exe"
    assert inv["node_count"] == 15

    lst = session.get(f"{API}/investigations")
    assert lst.status_code == 200
    arr = lst.json()
    assert len(arr) >= 1
    assert arr[0]["process_guid"] == PS_GUID  # newest first


def test_investigation_invalid_guid(session):
    r = session.post(f"{API}/investigations", json={"process_guid": "{bad}"})
    assert r.status_code == 404


# ---------- /api/search ----------
def test_search_by_image(session):
    r = session.get(f"{API}/search", params={"q": "powershell"})
    assert r.status_code == 200
    arr = r.json()
    assert any(x["image_name"] == "powershell.exe" and x["pid"] == 4820 for x in arr)


def test_search_by_pid(session):
    r = session.get(f"{API}/search", params={"q": "4820"})
    assert r.status_code == 200
    arr = r.json()
    assert any(x["pid"] == 4820 for x in arr)
