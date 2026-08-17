import re
from collections import Counter


CRITICAL_KEYWORDS = [
    "Failed password",
    "CRITICAL",
    "ERROR",
    "Permission denied"
]


def analyze_log(file_path):
    critical_logs = []
    event_types = []
    ip_addresses = []

    try:
        with open(file_path, "r") as file:

            print(f"[{file_path}] dosyası analiz ediliyor...\n")

            for line in file:
                line = line.strip()

                for keyword in CRITICAL_KEYWORDS:

                    if keyword.lower() in line.lower():

                        critical_logs.append(line)
                        event_types.append(keyword)

                        # IP adreslerini bul
                        ips = re.findall(
                            r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
                            line
                        )

                        ip_addresses.extend(ips)

                        break

        print("--- KRİTİK GÜVENLİK OLAYLARI RAPORU ---")

        print(f"Toplam {len(critical_logs)} kritik olay bulundu.\n")

        for log in critical_logs:
            print(log)

        print("\n--- OLAY TİPLERİ ---")

        counts = Counter(event_types)

        for event, count in counts.items():
            print(f"{event}: {count}")

        print("\n--- IP ADRESLERİ ---")

        if ip_addresses:
            ip_counts = Counter(ip_addresses)

            for ip, count in ip_counts.items():
                print(f"{ip}: {count} olay")
        else:
            print("Şüpheli IP adresi bulunamadı.")

    except FileNotFoundError:
        print(f"HATA: {file_path} bulunamadı.")


if __name__ == "__main__":
    LOG_FILE = "sample.log"
    analyze_log(LOG_FILE)