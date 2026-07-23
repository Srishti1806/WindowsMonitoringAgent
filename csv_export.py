import csv
from datetime import datetime

def export_csv(alerts):

    with open("reports/alerts.csv","w",newline="") as file:

        writer = csv.writer(file)

        writer.writerow([
            "Timestamp",
            "Alert"
        ])

        for alert in alerts:

            writer.writerow([
                datetime.now(),
                alert
            ])