# log_analyzer.py

# Analiz etmek istediğimiz kritik kelimeler listesi
CRITICAL_KEYWORDS = [
    "Failed password",  # Başarısız giriş denemeleri
    "CRITICAL",         # Kritik sistem hataları
    "ERROR",            # Hata mesajları
    "Permission denied",# Erişim reddi (Yetkilendirme sorunları)
]

def analyze_log(file_path):
    """
    Belirtilen log dosyasını okur, kritik kelimeleri arar ve raporlar.
    """
    critical_logs = []  # Kritik satırları depolayacağımız liste
    
    try:
        with open(file_path, 'r') as file:
            print(f"[{file_path}] dosyası analiz ediliyor...")
            
            # Dosyayı satır satır okuma döngüsü
            for line in file:
                line = line.strip() # Baştaki/sondaki boşlukları ve yeni satır karakterini temizler
                
                # Her kritik kelimeyi satırda arama döngüsü
                for keyword in CRITICAL_KEYWORDS:
                    
                    # 'in' operatörü ile kelimenin satırda olup olmadığını kontrol et
                    if keyword in line:
                        
                        # Eğer kritik bir kelime bulunursa, bu satırı listeye ekle
                        critical_logs.append(line)
                        
                        # Bu satırda bir kritik kelime bulunduktan sonra, diğer kelimeleri aramaya gerek yok.
                        # Bir sonraki satıra geçmek için break kullanılır.
                        break 
        
        # Analiz tamamlandıktan sonra sonuçları raporla
        if critical_logs:
            print("\n--- KRİTİK GÜVENLİK OLAYLARI RAPORU ---")
            print(f"Toplam {len(critical_logs)} kritik satır bulundu.")
            print("---------------------------------------")
            for log in critical_logs:
                print(log)
            print("---------------------------------------")
        else:
            print("\nAnaliz sonucunda kritik bir olay bulunamadı. Temiz log.")

    except FileNotFoundError:
        print(f"\nHATA: {file_path} bulunamadı. Lütfen dosya yolunu kontrol edin.")

# Script'i çalıştırmak için ana kısım
if __name__ == "__main__":
    LOG_FILE = "sample.log"
    analyze_log(LOG_FILE)
