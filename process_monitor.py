import psutil

def get_processes():
    processes = []

    for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe']):
        try:
            processes.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    return processes