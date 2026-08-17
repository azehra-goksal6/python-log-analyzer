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
    failed_login_ips = []

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

                        if keyword == "Failed password":
                            failed_login_ips.extend(ips)

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

        print("\n--- ŞÜPHELİ IP ADRESLERİ ---")

        failed_ip_counts = Counter(failed_login_ips)

        suspicious_found = False

        for ip, count in failed_ip_counts.items():
            if count >= 3:
                print(f"UYARI: {ip} adresinden {count} başarısız giriş!")
                suspicious_found = True

        if not suspicious_found:
            print("Şüpheli IP tespit edilmedi.")


                
        print("\n--- BRUTE-FORCE SALDIRISI TESPİTİ ---")

        brute_force_found = False

        for ip, count in failed_ip_counts.items():
            if count >= 3:
                print(
                    f"UYARI: {ip} adresinde olası brute-force saldırısı! "
                    f"{count} başarısız giriş tespit edildi."
                )
                brute_force_found = True

        if not brute_force_found:
            print("Brute-force saldırısı tespit edilmedi.")

        print("\n--- GÜVENLİK RİSK RAPORU ---")

        total_failed_logins = sum(failed_ip_counts.values())

        if total_failed_logins == 0:
            risk_level = "LOW"
        elif total_failed_logins <= 2:
            risk_level = "MEDIUM"
        elif total_failed_logins <= 5:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"

        print(f"Toplam başarısız giriş: {total_failed_logins}")
        print(f"Risk Seviyesi: {risk_level}")



    except FileNotFoundError:
        print(f"HATA: {file_path} bulunamadı.")


if __name__ == "__main__":
    LOG_FILE = "sample.log"
    analyze_log(LOG_FILE)