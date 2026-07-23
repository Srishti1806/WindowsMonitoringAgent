# Suspicious parent-child process relationships

suspicious_pairs = [
    ("WINWORD.EXE", "POWERSHELL.EXE"),
    ("EXCEL.EXE", "CMD.EXE"),
    ("OUTLOOK.EXE", "POWERSHELL.EXE"),
    ("WINWORD.EXE", "CMD.EXE")
]

# Whitelist of common processes

allowed = [
    "explorer.exe",
    "chrome.exe",
    "msedge.exe",
    "svchost.exe",
    "notepad.exe",
    "python.exe",
    "code.exe",
    "powershell.exe",
    "cmd.exe",
    "onedrive.exe",
    "runtimebroker.exe",
    "searchhost.exe",
    "searchindexer.exe",
    "taskhostw.exe",
    "sihost.exe",
    "dwm.exe",
    "ctfmon.exe",
    "ms-teams.exe"
]


def detect_parent_child(processes):
    alerts = []

    pid_map = {p['pid']: p for p in processes}

    for p in processes:
        parent = pid_map.get(p['ppid'])

        if parent and parent.get('name') and p.get('name'):

            pair = (
                parent['name'].upper(),
                p['name'].upper()
            )

            if pair in suspicious_pairs:
                alerts.append(
                    f"[HIGH] Suspicious Parent-Child: {parent['name']} -> {p['name']}"
                )

    return alerts


def detect_unknown(processes):
    alerts = []

    for p in processes:
        name = p.get('name')

        if name and name.lower() not in allowed:
            alerts.append(
                f"[MEDIUM] Unknown Process: {name}"
            )

    return alerts


def detect_suspicious_services(services):

    alerts = []

    suspicious_locations = [
        "temp",
        "appdata",
        "downloads"
    ]

    for service in services:

        path = str(service.get("path", "")).lower()

        for location in suspicious_locations:

            if location in path:

                alerts.append(
                    f"[HIGH] Suspicious Service: {service['name']} | Path: {service['path']}"
                )

    return alerts

    for service in services:
        path = str(service.get("path", "")).lower()

        for location in suspicious_locations:
            if location in path:
                alerts.append(
                    f"[HIGH] Suspicious Service: {service['name']} | Path: {service['path']}"
                )
def detect_suspicious_paths(processes):

    alerts = []

    suspicious = [
        "temp",
        "appdata",
        "downloads",
        "public"
    ]

    for p in processes:

        path = str(p.get("exe", "")).lower()

        for folder in suspicious:

            if folder in path:

                alerts.append(
                    f"[CRITICAL] Process running from suspicious path: {path}"
                )

    
    return alerts
def detect_suspicious_paths(processes):

    alerts = []

    suspicious_paths = [
        "temp",
        "appdata",
        "downloads",
        "public"
    ]

    for p in processes:

        path = str(p.get("exe", "")).lower()

        for folder in suspicious_paths:

            if folder in path:

                alerts.append(
                    f"[CRITICAL] Suspicious Path Detected: {path}"
                )

                break

    return alerts