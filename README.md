# Python Log Analyzer 🛡️

Python Log Analyzer, sistem log dosyalarını analiz ederek kritik güvenlik olaylarını tespit eden basit bir güvenlik analiz aracıdır.

Program; log dosyalarındaki başarısız giriş denemelerini, kritik sistem hatalarını, şüpheli IP adreslerini ve olası brute-force saldırılarını tespit ederek kullanıcıya güvenlik riskleri hakkında rapor sunar.

## 🚀 Özellikler

- Kritik güvenlik olaylarını tespit etme
- Başarısız giriş denemelerini analiz etme
- IP adreslerini tespit etme ve sayma
- Şüpheli IP adreslerini belirleme
- Başarısız giriş yapılan kullanıcı adlarını analiz etme
- Olası brute-force saldırılarını tespit etme
- Güvenlik risk seviyesini belirleme
- Başarısız girişlerin zaman analizini yapma
- Saldırı süresini hesaplama
- 60 saniye içerisindeki yoğun başarısız girişleri tespit etme
- Analiz sonuçlarını `security_report.txt` dosyasına kaydetme

## 🔍 Tespit Edilen Olaylar

Program aşağıdaki kritik ifadeleri analiz eder:

- `Failed password`
- `CRITICAL`
- `ERROR`
- `Permission denied`

Bu ifadelerin bulunduğu log satırları kritik güvenlik olayları olarak değerlendirilir.

## 📊 Güvenlik Analizi

Program analiz sonucunda aşağıdaki bilgileri gösterir.

### Olay Tipleri

Her kritik olay türünün kaç kez gerçekleştiğini gösterir.

Örnek:

```text
CRITICAL: 2
Failed password: 5
ERROR: 1    
```
### IP Adresleri

Log dosyalarında bulunan IP adreslerini ve kaç olayla ilişkili olduklarını gösterir.

Örnek:

```text
192.168.1.10: 4 olay
10.0.0.5: 2 olay
```
### Şüpheli IP Adresleri

Aynı IP adresinden 3 veya daha fazla başarısız giriş tespit edildiğinde uyarı oluşturulur.

Örnek:

```text
UYARI: 203.0.113.1 adresinden 4 başarısız giriş!
```
### Hedef Kullanıcılar

Başarısız giriş yapılmaya çalışılan kullanıcı adlarını ve her kullanıcı için başarısız giriş sayısını gösterir.

Örnek:

```text
root: 1 başarısız giriş
user2: 1 başarısız giriş
user: 3 başarısız giriş
```

### Brute-Force Saldırısı Tespiti

Aynı IP adresinden 3 veya daha fazla başarısız giriş tespit edilirse olası brute-force saldırısı olarak değerlendirilir.

Örnek:

```text
UYARI: 203.0.113.1 adresinde olası brute-force saldırısı! 4 başarısız giriş tespit edildi.
```

### Güvenlik Risk Seviyesi

Toplam başarısız giriş sayısına göre güvenlik risk seviyesi belirlenir.

Risk seviyeleri:

- `LOW` → Başarısız giriş bulunmadığında
- `MEDIUM` → 1-2 başarısız giriş olduğunda
- `HIGH` → 3-5 başarısız giriş olduğunda
- `CRITICAL` → 6 veya daha fazla başarısız giriş olduğunda

Örnek:

```text
Toplam başarısız giriş: 5
Risk Seviyesi: HIGH
```

### Saldırı Zaman Analizi

Başarısız girişlerin gerçekleştiği zamanlar analiz edilir.

Program:

- İlk başarısız giriş zamanını belirler.
- Son başarısız giriş zamanını belirler.
- Saldırının toplam süresini hesaplar.
- Toplam başarısız giriş sayısını gösterir.
- 60 saniye içerisinde 3 veya daha fazla başarısız giriş varsa yoğun başarısız giriş trafiği uyarısı oluşturur.

Örnek:

```text
--- SALDIRI ZAMAN ANALİZİ ---
İlk saldırı zamanı: Nov 25 10:00:20
Son saldırı zamanı: Nov 25 10:01:10
Saldırı süresi: 50 saniye
Toplam başarısız giriş: 5

UYARI: 60 saniye içerisinde 5 başarısız giriş tespit edildi!
Durum: YOĞUN BAŞARISIZ GİRİŞ TRAFİĞİ
```

## 📄 Güvenlik Raporu

Analiz sonucunda elde edilen bilgiler `security_report.txt` dosyasına kaydedilir.

Raporda aşağıdaki bilgiler bulunur:

- Toplam kritik olay sayısı
- Toplam başarısız giriş sayısı
- Güvenlik risk seviyesi
- Şüpheli IP adresleri
- Hedef kullanıcılar
- Saldırı zaman analizi
- Brute-force saldırısı tespiti

Örnek rapor:

```text
=== GÜVENLİK RAPORU ===
Toplam kritik olay: 5
Toplam başarısız giriş: 5
Risk Seviyesi: HIGH

Şüpheli IP Adresleri:
203.0.113.1 -> 4 başarısız giriş

Hedef Kullanıcılar:
root -> 1 başarısız giriş
user2 -> 1 başarısız giriş
user -> 3 başarısız giriş

Saldırı Zaman Analizi:
İlk saldırı zamanı: Nov 25 10:00:20
Son saldırı zamanı: Nov 25 10:01:10
Saldırı süresi: 50 saniye
Toplam başarısız giriş: 5
UYARI: 60 saniye içerisinde 5 başarısız giriş tespit edildi!
Durum: YOĞUN BAŞARISIZ GİRİŞ TRAFİĞİ

Brute-force:
203.0.113.1 -> TESPİT EDİLDİ (4 başarısız giriş)
```

## ▶️ Kullanım

Projeyi çalıştırmak için Python'un sisteminizde kurulu olması gerekir.

Terminal üzerinden proje klasörüne gidildikten sonra aşağıdaki komut çalıştırılır:

```bash
python log_analyzer.py
```

Program varsayılan olarak `sample.log` dosyasını analiz eder.

```python
LOG_FILE = "sample.log"
analyze_log(LOG_FILE)
```

Farklı bir log dosyasını analiz etmek için `LOG_FILE` değişkeni değiştirilebilir.

## 📁 Proje Dosyaları

```text
python-log-analyzer/
│
├── log_analyzer.py
├── sample.log
├── security_report.txt
├── README.md
└── .gitignore
```

### Dosyaların Görevleri

**`log_analyzer.py`**

Log dosyasını analiz eden Python programıdır.

**`sample.log`**

Analiz işlemi için kullanılan örnek sistem log dosyasıdır.

**`security_report.txt`**

Analiz sonucunda oluşturulan güvenlik raporudur.

**`README.md`**

Projenin amacı, özellikleri ve kullanım bilgilerini içeren dokümantasyon dosyasıdır.

**`.gitignore`**

Git tarafından takip edilmemesi gereken dosyaları belirtmek için kullanılır.

## 🛠️ Kullanılan Teknolojiler

- Python 3
- `re` modülü
- `collections.Counter`
- `datetime` modülü

## 🎯 Projenin Amacı

Bu proje, Python kullanarak temel log analizi ve güvenlik olaylarının tespit edilmesini öğrenmek amacıyla geliştirilmiştir.

Proje kapsamında:

- Dosya okuma
- Düzenli ifadeler (Regular Expressions)
- Veri sayımı
- IP adresi tespiti
- Kullanıcı adı analizi
- Zaman analizi
- Güvenlik risk değerlendirmesi
- Rapor oluşturma

gibi temel konular uygulanmıştır.

## 📌 Not

Bu proje eğitim amaçlı geliştirilmiş basit bir log analiz aracıdır. Gerçek üretim sistemlerinde kullanılmadan önce daha gelişmiş log formatı desteği, IP doğrulama, farklı saldırı türlerinin tespiti ve daha kapsamlı güvenlik kuralları eklenmelidir.