import wmi

def get_services():
    c = wmi.WMI()

    services = []

    for s in c.Win32_Service():
        services.append({
            "name": s.Name,
            "state": s.State,
            "path": s.PathName
        })

    return services