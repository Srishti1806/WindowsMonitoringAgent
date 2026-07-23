from process_monitor import get_processes
from service_audit import get_services
from csv_export import export_csv

from detection_engine import (
    detect_parent_child,
    detect_unknown,
    detect_suspicious_services,
     detect_suspicious_paths
)

from alerts import save_alerts
from report_generator import generate_report
from csv_export import export_csv



def main():

    print("Windows Monitoring Agent Started...\n")

    print("Scanning processes...")
    processes = get_processes()

    print("Scanning services...")
    services = get_services()

    alerts = []

    alerts.extend(
        detect_parent_child(processes)
    )

    alerts.extend(
        detect_unknown(processes)
    )

    alerts.extend(
        detect_suspicious_services(services)
    )
    alerts.extend(
    detect_suspicious_paths(processes)
)

    save_alerts(alerts)

    generate_report(alerts)

    print("\n===== ALERTS =====")

    if alerts:
        for alert in alerts:
            print(alert)
    else:
        print("No suspicious activity detected.")

    print("\nMonitoring Completed Successfully.")


if __name__ == "__main__":
    main()
  #  import time

#if __name__ == "__main__":
   # while True:
    #    print("\nRunning Security Scan...\n")
     #   main()
      #  time.sleep(30)