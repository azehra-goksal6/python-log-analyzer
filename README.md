# Python Log Analyzer 🛡️

Python Log Analyzer, sistem log dosyalarını analiz ederek kritik güvenlik olaylarını tespit eden basit bir güvenlik analiz aracıdır.

Program, log dosyalarındaki başarısız giriş denemelerini, kritik sistem hatalarını, şüpheli IP adreslerini ve olası brute-force saldırılarını tespit ederek kullanıcıya güvenlik riskleri hakkında rapor sunar.

## 🚀 Özellikler

- Kritik güvenlik olaylarını tespit etme
- Başarısız giriş denemelerini analiz etme
- IP adreslerini tespit etme ve sayma
- Şüpheli IP adreslerini belirleme
- Başarısız giriş yapılan kullanıcı adlarını analiz etme
- Olası brute-force saldırılarını tespit etme
- Güvenlik risk seviyesini belirleme
- Başarısız girişlerin zaman analizini yapma
- En yoğun saldırı zamanını belirleme
- Analiz sonuçlarını `security_report.txt` dosyasına kaydetme

## 🔍 Tespit Edilen Olaylar

Program aşağıdaki kritik ifadeleri analiz eder:

- `Failed password`
- `CRITICAL`
- `ERROR`
- `Permission denied`

Bu ifadeler bulunan log satırları kritik güvenlik olayları olarak değerlendirilir.

## 📊 Güvenlik Analizi

Program analiz sonucunda aşağıdaki bilgileri gösterir:

### Olay Tipleri

Her kritik olay türünün kaç kez gerçekleştiğini gösterir.

### IP Adresleri

Log dosyalarında bulunan IP adreslerini ve kaç olayla ilişkili olduklarını gösterir.

### Şüpheli IP Adresleri

Aynı IP adresinden 3 veya daha fazla başarısız giriş tespit edildiğinde uyarı oluşturulur.

Örnek:

```text
UYARI: 203.0.113.1 adresinden 4 başarısız giriş!
