# Python Log Analyzer

Python ile geliştirilmiş basit bir güvenlik log analiz aracıdır.

Bu proje, log dosyalarını analiz ederek kritik güvenlik olaylarını, başarısız giriş denemelerini, şüpheli IP adreslerini, hedef kullanıcıları ve olası brute-force saldırılarını tespit eder.

## Özellikler

- Kritik güvenlik olaylarını tespit etme
- Başarısız parola denemelerini analiz etme
- IP adreslerini çıkarma ve olay sayılarını hesaplama
- Şüpheli IP adreslerini tespit etme
- Başarısız giriş yapılan kullanıcıları analiz etme
- Olası brute-force saldırılarını tespit etme
- Güvenlik risk seviyesini belirleme
- Saldırı zamanlarını analiz etme
- En yoğun saldırı zamanını belirleme
- Güvenlik raporunu `security_report.txt` dosyasına kaydetme

## Tespit Edilen Kritik Olaylar

Program aşağıdaki kritik anahtar kelimeleri kullanarak logları analiz eder:

- `Failed password`
- `CRITICAL`
- `ERROR`
- `Permission denied`

## Nasıl Çalışır?

Program verilen log dosyasını satır satır okur.

Kritik bir olay tespit edildiğinde:

1. Kritik olay kaydedilir.
2. Olay türü belirlenir.
3. Log satırındaki IP adresleri çıkarılır.
4. Başarısız girişlerde hedef kullanıcı belirlenir.
5. Aynı IP adresinden gelen başarısız girişler sayılır.
6. Belirli sayının üzerindeki başarısız girişler şüpheli olarak değerlendirilir.
7. Olası brute-force saldırıları tespit edilir.
8. Genel güvenlik risk seviyesi hesaplanır.
9. Başarısız girişlerin zamanları analiz edilir.
10. Sonuçlar güvenlik raporuna kaydedilir.

## Risk Seviyesi

Program başarısız giriş sayılarına göre risk seviyesini belirler:

| Başarısız Giriş | Risk Seviyesi |
|---|---|
| 0 | LOW |
| 1-2 | MEDIUM |
| 3-5 | HIGH |
| 6+ | CRITICAL |

## Örnek Çıktı

```text
--- OLAY TİPLERİ ---
CRITICAL: 2
Failed password: 5
ERROR: 1

--- IP ADRESLERİ ---
10.0.0.5: 1 olay
203.0.113.1: 4 olay

--- ŞÜPHELİ IP ADRESLERİ ---
UYARI: 203.0.113.1 adresinden 4 başarısız giriş!

--- HEDEF KULLANICILAR ---
root: 1 başarısız giriş
user2: 1 başarısız giriş
user: 3 başarısız giriş

--- BRUTE-FORCE SALDIRISI TESPİTİ ---
UYARI: 203.0.113.1 adresinde olası brute-force saldırısı!
4 başarısız giriş tespit edildi.

--- GÜVENLİK RİSK RAPORU ---
Toplam başarısız giriş: 5
Risk Seviyesi: HIGH

--- SALDIRI ZAMAN ANALİZİ ---
Nov 25 10:00:20: 1 başarısız giriş
Nov 25 10:00:30: 1 başarısız giriş
Nov 25 10:01:00: 1 başarısız giriş
Nov 25 10:01:05: 1 başarısız giriş
Nov 25 10:01:10: 1 başarısız giriş