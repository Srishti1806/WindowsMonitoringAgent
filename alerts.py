from datetime import datetime
import os

def save_alerts(alerts):

    os.makedirs("logs", exist_ok=True)

    with open("logs/alerts.txt", "a") as file:

        file.write("\n")
        file.write("=" * 60)
        file.write("\n")

        for alert in alerts:
            file.write(
                f"{datetime.now()} : {alert}\n"
            )