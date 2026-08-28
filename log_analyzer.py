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
    usernames = []
    failed_login_ips = []
    report_lines = []
    attack_times = []
    failed_login_events = []



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

                        # Başarısız giriş yapan IP'leri kaydet
                        if keyword == "Failed password":

                            time_match = re.search(
                                r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',
                                line
                            )

                            username = None
                            timestamp = None

                            if time_match:
                                timestamp = time_match.group(1)
                                attack_times.append(timestamp)

                            user_match = re.search(
                                r'Failed password for (?:invalid user )?(\w+)',
                                line,
                                re.IGNORECASE
                            )

                            if user_match:
                                username = user_match.group(1)
                                usernames.append(username)

                            failed_login_ips.extend(ips)

                            if ips:
                                failed_login_events.append({
                                    "ip": ips[0],
                                    "username": username,
                                    "time": timestamp
                                })    
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


        print("\n--- HEDEF KULLANICILAR ---")

        if usernames:
            user_counts = Counter(usernames)

            for user, count in user_counts.items():
                print(f"{user}: {count} başarısız giriş")
        else:
            print("Kullanıcı bilgisi bulunamadı.")

                
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

        print("\n--- SALDIRI ZAMAN ANALİZİ ---")

        if attack_times:
            from datetime import datetime

            attack_datetimes = []

            for time in attack_times:
                try:
                    attack_datetimes.append(
                        datetime.strptime(f"2025 {time}", "%Y %b %d %H:%M:%S")
                    )
                except ValueError:
                    continue

            if attack_datetimes:
                first_attack = min(attack_datetimes)
                last_attack = max(attack_datetimes)

                duration = last_attack - first_attack
                total_attack_count = len(attack_datetimes)

                print(f"İlk saldırı zamanı: {first_attack.strftime('%b %d %H:%M:%S')}")
                print(f"Son saldırı zamanı: {last_attack.strftime('%b %d %H:%M:%S')}")
                print(f"Saldırı süresi: {duration.total_seconds():.0f} saniye")
                print(f"Toplam başarısız giriş: {total_attack_count}")

                if duration.total_seconds() <= 60 and total_attack_count >= 3:
                    print(
                        f"\nUYARI: 60 saniye içerisinde "
                        f"{total_attack_count} başarısız giriş tespit edildi!"
                    )
                    print("Durum: YOĞUN BAŞARISIZ GİRİŞ TRAFİĞİ")
                else:
                    print("\nDurum: Normal")

            else:
                print("Saldırı zamanı analiz edilemedi.")

        else:
            print("Saldırı zamanı tespit edilemedi.")


        report_lines.append("=== GÜVENLİK RAPORU ===")
        report_lines.append(f"Toplam kritik olay: {len(critical_logs)}")
        report_lines.append(f"Toplam başarısız giriş: {total_failed_logins}")
        report_lines.append(f"Risk Seviyesi: {risk_level}")

        report_lines.append("\nŞüpheli IP Adresleri:")

        for ip, count in failed_ip_counts.items():
            if count >= 3:
                report_lines.append(
                    f"{ip} -> {count} başarısız giriş"
                )

        report_lines.append("\nHedef Kullanıcılar:")

        for user, count in Counter(usernames).items():
            report_lines.append(
                f"{user} -> {count} başarısız giriş"
            )
        report_lines.append("\nSaldırı Zaman Analizi:")

        if attack_datetimes:
            report_lines.append(
                f"İlk saldırı zamanı: {first_attack.strftime('%b %d %H:%M:%S')}"
            )
            report_lines.append(
                f"Son saldırı zamanı: {last_attack.strftime('%b %d %H:%M:%S')}"
            )
            report_lines.append(
                f"Saldırı süresi: {duration.total_seconds():.0f} saniye"
            )
            report_lines.append(
                f"Toplam başarısız giriş: {total_attack_count}"
            )

            if duration.total_seconds() <= 60 and total_attack_count >= 3:
                report_lines.append(
                    f"UYARI: 60 saniye içerisinde {total_attack_count} "
                    "başarısız giriş tespit edildi!"
                )
                report_lines.append("Durum: YOĞUN BAŞARISIZ GİRİŞ TRAFİĞİ")
            else:
                report_lines.append("Durum: Normal")
        else:
            report_lines.append("Saldırı zamanı analiz edilemedi.")


        report_lines.append("\nBrute-force:")

        if brute_force_found:
            for ip, count in failed_ip_counts.items():
                if count >= 3:
                    report_lines.append(
                        f"{ip} -> TESPİT EDİLDİ ({count} başarısız giriş)"
                    )
        else:
            report_lines.append("Tespit edilmedi.")

        with open("security_report.txt", "w", encoding="utf-8") as report_file:
            report_file.write("\n".join(report_lines))

        print("\nGüvenlik raporu security_report.txt dosyasına kaydedildi.")




    except FileNotFoundError:
        print(f"HATA: {file_path} bulunamadı.")


if __name__ == "__main__":
    LOG_FILE = "sample.log"
    analyze_log(LOG_FILE)