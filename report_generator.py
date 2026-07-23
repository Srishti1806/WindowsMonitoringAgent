from datetime import datetime
import os

def generate_report(alerts):

    os.makedirs("reports", exist_ok=True)

    report_file = "reports/report.txt"

    with open(report_file, "w") as file:

        file.write("WINDOWS SERVICE & PROCESS MONITORING REPORT\n")
        file.write("=" * 60 + "\n\n")

        file.write(f"Generated On: {datetime.now()}\n\n")

        file.write(f"Total Alerts: {len(alerts)}\n\n")

        file.write("DETECTED ALERTS\n")
        file.write("-" * 60 + "\n")

        if alerts:
            for alert in alerts:
                file.write(alert + "\n")
        else:
            file.write("No suspicious activity detected.\n")

    print(f"\nReport saved to: {report_file}")