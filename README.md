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