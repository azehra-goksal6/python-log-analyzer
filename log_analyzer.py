CRITICAL_KEYWORDS = [
    "Failed password",
    "CRITICAL",
    "ERROR",
    "Permission denied"
]


def analyze_log(file_path):
    """Belirtilen log dosyasını okur, kritik kelimeleri arar ve raporlar."""
    critical_logs = []

    try:
        with open(file_path, 'r') as file:
            print(f"[{file_path}] dosyası analiz ediliyor...")

            for line in file:
                line = line.strip()

                for keyword in CRITICAL_KEYWORDS:
                    if keyword in line:
                        critical_logs.append(line)
                        break

        if critical_logs:
            print("\n--- KRİTİK GÜVENLİK OLAYLARI RAPORU ---")
            print(f"Toplam {len(critical_logs)} kritik satır bulundu.")
            print("----------------------------------------")

            for log in critical_logs:
                print(log)

            print("----------------------------------------")
        else:
            print("\nAnaliz sonucunda kritik bir olay bulunamadı. Temiz log.")

    except FileNotFoundError:
        print(f"\nHATA: {file_path} bulunamadı. Lütfen dosya yolunu kontrol edin.")


if __name__ == "__main__":
    LOG_FILE = "sample.log"
    analyze_log(LOG_FILE)
